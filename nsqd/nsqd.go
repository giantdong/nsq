package nsqd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kulv2012/nsq/internal/clusterinfo"
	"github.com/kulv2012/nsq/internal/dirlock"
	"github.com/kulv2012/nsq/internal/http_api"
	"github.com/kulv2012/nsq/internal/lg"
	"github.com/kulv2012/nsq/internal/protocol"
	"github.com/kulv2012/nsq/internal/statsd"
	"github.com/kulv2012/nsq/internal/util"
	"github.com/kulv2012/nsq/internal/version"
)

const (
	TLSNotRequired = iota
	TLSRequiredExceptHTTP
	TLSRequired
)

type errStore struct {
	err error
}

type NSQD struct {
	// 64bit atomic vars need to be first for proper alignment on 32bit platforms
	clientIDSequence int64

	sync.RWMutex

	opts atomic.Value

	dl        *dirlock.DirLock
	isLoading int32
	errValue  atomic.Value
	startTime time.Time

	topicMap map[string]*Topic

	lookupPeers atomic.Value

	tcpListener   net.Listener
	httpListener  net.Listener
	httpsListener net.Listener
	tlsConfig     *tls.Config

	poolSize int

	notifyChan           chan interface{}
	optsNotificationChan chan struct{}
	exitChan             chan int
	waitGroup            util.WaitGroupWrapper

	ci *clusterinfo.ClusterInfo
}

func New(opts *Options) *NSQD {
	//初始化NSQD结构，加锁数据目录，初始化https配置
	dataPath := opts.DataPath
	if opts.DataPath == "" {
		cwd, _ := os.Getwd()
		dataPath = cwd
	}
	if opts.Logger == nil {
		opts.Logger = log.New(os.Stderr, opts.LogPrefix, log.Ldate|log.Ltime|log.Lmicroseconds)
	}

	n := &NSQD{
		startTime:            time.Now(),
		topicMap:             make(map[string]*Topic),
		exitChan:             make(chan int),
		notifyChan:           make(chan interface{}),
		optsNotificationChan: make(chan struct{}, 1),
		dl:                   dirlock.New(dataPath),
	}
	httpcli := http_api.NewClient(nil, opts.HTTPClientConnectTimeout, opts.HTTPClientRequestTimeout)
	n.ci = clusterinfo.New(n.logf, httpcli)

	n.swapOpts(opts)
	n.errValue.Store(errStore{})

	var err error
	opts.logLevel, err = lg.ParseLogLevel(opts.LogLevel, opts.Verbose)
	if err != nil {
		n.logf(LOG_FATAL, "%s", err)
		os.Exit(1)
	}

	//调用syscall.Flock锁住这个目录，避免设置同一个data目录重复运行
	err = n.dl.Lock()
	if err != nil {
		n.logf(LOG_FATAL, "--data-path=%s in use (possibly by another instance of nsqd)", dataPath)
		os.Exit(1)
	}

	if opts.MaxDeflateLevel < 1 || opts.MaxDeflateLevel > 9 {
		n.logf(LOG_FATAL, "--max-deflate-level must be [1,9]")
		os.Exit(1)
	}

	if opts.ID < 0 || opts.ID >= 1024 {
		n.logf(LOG_FATAL, "--node-id must be [0,1024)")
		os.Exit(1)
	}

	if opts.StatsdPrefix != "" {
		var port string
		_, port, err = net.SplitHostPort(opts.HTTPAddress)
		if err != nil {
			n.logf(LOG_FATAL, "failed to parse HTTP address (%s) - %s", opts.HTTPAddress, err)
			os.Exit(1)
		}
		statsdHostKey := statsd.HostKey(net.JoinHostPort(opts.BroadcastAddress, port))
		prefixWithHost := strings.Replace(opts.StatsdPrefix, "%s", statsdHostKey, -1)
		if prefixWithHost[len(prefixWithHost)-1] != '.' {
			prefixWithHost += "."
		}
		opts.StatsdPrefix = prefixWithHost
	}

	//下面进行https相关的初始化配置
	if opts.TLSClientAuthPolicy != "" && opts.TLSRequired == TLSNotRequired {
		opts.TLSRequired = TLSRequired
	}

	tlsConfig, err := buildTLSConfig(opts)
	if err != nil {
		n.logf(LOG_FATAL, "failed to build TLS config - %s", err)
		os.Exit(1)
	}
	if tlsConfig == nil && opts.TLSRequired != TLSNotRequired {
		n.logf(LOG_FATAL, "cannot require TLS client connections without TLS key and cert")
		os.Exit(1)
	}
	n.tlsConfig = tlsConfig

	for _, v := range opts.E2EProcessingLatencyPercentiles {
		if v <= 0 || v > 1 {
			n.logf(LOG_FATAL, "Invalid percentile: %v", v)
			os.Exit(1)
		}
	}

	n.logf(LOG_INFO, version.String("nsqd"))
	n.logf(LOG_INFO, "ID: %d", opts.ID)

	return n
}

func (n *NSQD) getOpts() *Options {
	return n.opts.Load().(*Options)
}

func (n *NSQD) swapOpts(opts *Options) {
	n.opts.Store(opts)
}

func (n *NSQD) triggerOptsNotification() {
	select {
	case n.optsNotificationChan <- struct{}{}:
	default:
	}
}

func (n *NSQD) RealTCPAddr() *net.TCPAddr {
	n.RLock()
	defer n.RUnlock()
	return n.tcpListener.Addr().(*net.TCPAddr)
}

func (n *NSQD) RealHTTPAddr() *net.TCPAddr {
	n.RLock()
	defer n.RUnlock()
	return n.httpListener.Addr().(*net.TCPAddr)
}

func (n *NSQD) RealHTTPSAddr() *net.TCPAddr {
	n.RLock()
	defer n.RUnlock()
	return n.httpsListener.Addr().(*net.TCPAddr)
}

func (n *NSQD) SetHealth(err error) {
	n.errValue.Store(errStore{err: err})
}

func (n *NSQD) IsHealthy() bool {
	return n.GetError() == nil
}

func (n *NSQD) GetError() error {
	errValue := n.errValue.Load()
	return errValue.(errStore).err
}

func (n *NSQD) GetHealth() string {
	err := n.GetError()
	if err != nil {
		return fmt.Sprintf("NOK - %s", err)
	}
	return "OK"
}

func (n *NSQD) GetStartTime() time.Time {
	return n.startTime
}

func (n *NSQD) Main() {
	//开启各个端口监听客户端请求，创建各项后台携程进行处理
	var httpListener net.Listener
	var httpsListener net.Listener

	//初始化一个context的指针，里面就
	ctx := &context{n}

	//创建TCP协议的监听句柄监听请求
	tcpListener, err := net.Listen("tcp", n.getOpts().TCPAddress)
	if err != nil {
		n.logf(LOG_FATAL, "listen (%s) failed - %s", n.getOpts().TCPAddress, err)
		os.Exit(1)
	}
	n.Lock()
	n.tcpListener = tcpListener
	n.Unlock()
	//tcpServer是个接口，里面有个context的指针，之外就是Handle函数了，函数读取协议版本然后调用prot.IOLoop进行消息读取和解析
	//处理流程在internal/protocol/tcp_server.go 
	tcpServer := &tcpServer{ctx: ctx}
	n.waitGroup.Wrap(func() {
		//循环accept客户端请求，然后创建协程进行消息读写循环prot.IOLoop(clientConn)
		protocol.TCPServer(n.tcpListener, tcpServer, n.logf)
	})

	//创建HTTPS协议的监听句柄监听请求
	if n.tlsConfig != nil && n.getOpts().HTTPSAddress != "" {
		httpsListener, err = tls.Listen("tcp", n.getOpts().HTTPSAddress, n.tlsConfig)
		if err != nil {
			n.logf(LOG_FATAL, "listen (%s) failed - %s", n.getOpts().HTTPSAddress, err)
			os.Exit(1)
		}
		n.Lock()
		n.httpsListener = httpsListener
		n.Unlock()
		//创建http接口httpServer类，用来接收https协议的请求
		httpsServer := newHTTPServer(ctx, true, true)
		n.waitGroup.Wrap(func() {
			//开始监听处理请求, http_api.serve 在internal/http_api/http_server.go 
			http_api.Serve(n.httpsListener, httpsServer, "HTTPS", n.logf)
		})
	}

	//下面常规初始化http链接，开始监听请求
	//创建HTTP协议的监听句柄监听请求, 0.0.0.0:4151
	httpListener, err = net.Listen("tcp", n.getOpts().HTTPAddress)
	if err != nil {
		n.logf(LOG_FATAL, "listen (%s) failed - %s", n.getOpts().HTTPAddress, err)
		os.Exit(1)
	}
	n.Lock()
	n.httpListener = httpListener
	n.Unlock()
	//https跟http的处理函数是一样的，这是https的listener不一样,也就是底层网络处理函数不一样
	httpServer := newHTTPServer(ctx, false, n.getOpts().TLSRequired == TLSRequired)
	n.waitGroup.Wrap(func() {
		//开始监听请求, httpListener是连接通道，httpServer 是处理相关的函数
		http_api.Serve(n.httpListener, httpServer, "HTTP", n.logf)
	})

	//队列scan扫描协程
	n.waitGroup.Wrap(func() { n.queueScanLoop() })
	//lookup的查找协程
	n.waitGroup.Wrap(func() { n.lookupLoop() })
	//如果配置了状态地址，开启状态协程
	if n.getOpts().StatsdAddress != "" {
		n.waitGroup.Wrap(func() { n.statsdLoop() })
	}
	//至此main函数结束，上面基本上开启了tcp，https,http协程开始不断accept客户端请求并且进行处理
	//main结束后返回到program.Start， 后者退出后返回到svc的代码里面进行等待，监听信号量如果用户杀进程, 就调用program.Stop函数
	//stop函数实际上调用到了p.nsqd.Exit()
}

//下面用了struct的tag 功能
type meta struct {
	Topics []struct {
		Name     string `json:"name"`
		Paused   bool   `json:"paused"`
		Channels []struct {
			Name   string `json:"name"`
			Paused bool   `json:"paused"`
		} `json:"channels"`
	} `json:"topics"`
}

func newMetadataFile(opts *Options) string {
	return path.Join(opts.DataPath, "nsqd.dat")
}

func oldMetadataFile(opts *Options) string {
	return path.Join(opts.DataPath, fmt.Sprintf("nsqd.%d.dat", opts.ID))
}

func readOrEmpty(fn string) ([]byte, error) {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read metadata from %s - %s", fn, err)
		}
	}
	return data, nil
}

func writeSyncFile(fn string, data []byte) error {
	f, err := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	f.Close()
	return err
}

func (n *NSQD) LoadMetadata() error {
	//program.Start,  topic有变动时都会调用这里来持久化调用这里
	atomic.StoreInt32(&n.isLoading, 1)
	defer atomic.StoreInt32(&n.isLoading, 0)

	fn := newMetadataFile(n.getOpts())
	// old metadata filename with ID, maintained in parallel to enable roll-back
	//old文件似乎是个软连接
	fnID := oldMetadataFile(n.getOpts())

	//读取当前的nsqd.dat文件内容
	data, err := readOrEmpty(fn)
	if err != nil {
		return err
	}
	dataID, errID := readOrEmpty(fnID)
	if errID != nil {
		return errID
	}

	if data == nil && dataID == nil {
		return nil // fresh start
	}
	if data != nil && dataID != nil {
		if bytes.Compare(data, dataID) != 0 {
			return fmt.Errorf("metadata in %s and %s do not match (delete one)", fn, fnID)
		}
	}
	if data == nil {
		// only old metadata file exists, use it
		fn = fnID
		data = dataID
	}

	var m meta
	//将读取到的文件内容转为json使用，方便
	err = json.Unmarshal(data, &m)
	if err != nil {
		return fmt.Errorf("failed to parse metadata in %s - %s", fn, err)
	}

	//下面先循环topic然后递归扫描其channel列表
	for _, t := range m.Topics {
		if !protocol.IsValidTopicName(t.Name) {
			n.logf(LOG_WARN, "skipping creation of invalid topic %s", t.Name)
			continue
		}
		//创建或者获取一个topic,如果没有就创建他，并且开启消息协程
		topic := n.GetTopic(t.Name)
		if t.Paused {
			topic.Pause()
		}

		//再递归其channel
		for _, c := range t.Channels {
			if !protocol.IsValidChannelName(c.Name) {
				n.logf(LOG_WARN, "skipping creation of invalid channel %s", c.Name)
				continue
			}
			///获取topic的channel，如果之前没有是新建的，则通知channelUpdateChan 去刷新订阅状态
			channel := topic.GetChannel(c.Name)
			if c.Paused {
				channel.Pause()
			}
		}
	}
	return nil
}

func (n *NSQD) PersistMetadata() error {
	//持久化当前的topic,channel 数据结构，不涉及到数据不封顶持久化. 写入临时文件后改名
	//exit退出时也会写入本地元数据
	// persist metadata about what topics/channels we have, across restarts
	//这个文件就是nsqd.data
	fileName := newMetadataFile(n.getOpts())
	// old metadata filename with ID, maintained in parallel to enable roll-back
	//这文件就是nsqd.$ID.data的软连接， 用来做回滚操作的，具体后面了解一下
	fileNameID := oldMetadataFile(n.getOpts())

	n.logf(LOG_INFO, "NSQ: persisting topic/channel metadata to %s", fileName)

	js := make(map[string]interface{})
	topics := []interface{}{}
	for _, topic := range n.topicMap {
		if topic.ephemeral {
			continue
		}
		topicData := make(map[string]interface{})
		topicData["name"] = topic.name
		topicData["paused"] = topic.IsPaused()
		channels := []interface{}{}
		topic.Lock()
		for _, channel := range topic.channelMap {
			channel.Lock()
			if channel.ephemeral {
				channel.Unlock()
				continue
			}
			channelData := make(map[string]interface{})
			channelData["name"] = channel.name
			channelData["paused"] = channel.IsPaused()
			channels = append(channels, channelData)
			channel.Unlock()
		}
		topic.Unlock()
		topicData["channels"] = channels
		topics = append(topics, topicData)
	}
	js["version"] = version.Binary
	js["topics"] = topics

	data, err := json.Marshal(&js)//序列号成json数据
	if err != nil {
		return err
	}

	
	//下面写了2次文件，第一次是json 数据文件，写好后重命名；
	//先写入临时文件，然后做一次重命名，这样避免中间出问题只写了一部分数据，rename是原子操作,所以安全
	tmpFileName := fmt.Sprintf("%s.%d.tmp", fileName, rand.Int())

	err = writeSyncFile(tmpFileName, data)
	if err != nil {
		return err
	}
	//原子操作重命名文件
	err = os.Rename(tmpFileName, fileName)
	if err != nil {
		return err
	}
	// technically should fsync DataPath here

	stat, err := os.Lstat(fileNameID)
	if err == nil && stat.Mode()&os.ModeSymlink != 0 {
		//如果有符号链接，那OK，不用管了
		return nil
	}

	// if no symlink (yet), race condition:
	// crash right here may cause next startup to see metadata conflict and abort
	//接下来建立软连接到fileNameID， 如果是非windows系统，直接时文件建立软连接到fileName，然后 nsqd.%d.dat 指向了刚刚的临时文件，实际上都指向了nsqd.dat
	tmpFileNameID := fmt.Sprintf("%s.%d.tmp", fileNameID, rand.Int())

	if runtime.GOOS != "windows" {
		//又搞个临时软连接，映射到nsqd.data
		err = os.Symlink(fileName, tmpFileNameID)
	} else {
		// on Windows need Administrator privs to Symlink
		// instead write copy every time
		err = writeSyncFile(tmpFileNameID, data)
	}
	if err != nil {
		return err
	}
	//临时软连接改为正常软连接, 这里不直接Symlink 的原因是？ 为了能跟windows统一？
	err = os.Rename(tmpFileNameID, fileNameID)
	if err != nil {
		return err
	}
	// technically should fsync DataPath here

	return nil
}

func (n *NSQD) Exit() {
	//main结束后返回到program.Start， 后者退出后返回到svc的代码里面进行等待，监听信号量如果用户杀进程, 就调用program.Stop函数
	//program调用这里退出程序，需要关闭监听句柄和其他 句柄，然后持久化数据
	//下面一个个停止相关的句柄，停止接听请求
	if n.tcpListener != nil {
		n.tcpListener.Close()
	}

	if n.httpListener != nil {
		n.httpListener.Close()
	}

	if n.httpsListener != nil {
		n.httpsListener.Close()
	}

	n.Lock()
	//加锁状态下持久化channel状态到磁盘
	err := n.PersistMetadata()
	if err != nil {
		n.logf(LOG_ERROR, "failed to persist metadata - %s", err)
	}
	n.logf(LOG_INFO, "NSQ: closing topics")
	for _, topic := range n.topicMap {
		topic.Close()
	}
	n.Unlock()

	//给所有携程发送退出信号
	close(n.exitChan)
	//等待所有等在这个waitgroup的携程退出
	n.waitGroup.Wait()

	n.dl.Unlock()
}

// GetTopic performs a thread safe operation
// to return a pointer to a Topic object (potentially new)
func (n *NSQD) GetTopic(topicName string) *Topic {
	// most likely, we already have this topic, so try read lock first.
	//如上面所说，大部分情况都是存在topic的，这优化值得
	n.RLock()
	t, ok := n.topicMap[topicName]
	n.RUnlock()
	if ok {
		return t
	}

	//不存在这topc，得new一个了,  所以直接加锁了整个nsqd结构
	n.Lock()

	t, ok = n.topicMap[topicName]
	if ok { //还有种情况，就在刚才那一瞬间，有其他协程进来了，他new了一个，所以获取锁后还得判断一下是否存在
		n.Unlock()
		return t
	}
	deleteCallback := func(t *Topic) {
		//topic的删除函数
		n.DeleteExistingTopic(t.name)
	}
	//创建一个topic结构，并且里面初始化好diskqueue, 加入到NSQD的topicmap里面
	//创建topic的时候，会开启消息协程
	t = NewTopic(topicName, &context{n}, deleteCallback)
	n.topicMap[topicName] = t

	n.logf(LOG_INFO, "TOPIC(%s): created", t.name)

	// release our global nsqd lock, and switch to a more granular topic lock while we init our
	// channels from lookupd. This blocks concurrent PutMessages to this topic.
	//可以理解为先加锁topic，这个时候会加不上吗？
	//不会，因为我们在获取topic的时候，会先加nsqd的读锁获取topic，然后再第二步进行PutMessage或者DeleteExistingChannel的时候，会加RLock或者Lock；
	//因此，由于本函数开头已经先加了n.Lock()大锁，所以上面第二步不可能进入，因此下面可以直接加t.Lock而不用担心死锁
	//这里相当于已经创建了topic到nsqd的topicMap，接下来的事情不涉及到nsqd，而只是topic内部的事情了，所以换一把小一点的锁
	t.Lock()
	n.Unlock()

	//lookupd里面存储所有之前的channel信息，所以这里加载一下，这样消息能不丢
	// if using lookupd, make a blocking call to get the topics, and immediately create them.
	// this makes sure that any message received is buffered to the right channels
	lookupdHTTPAddrs := n.lookupdHTTPAddrs()
	if len(lookupdHTTPAddrs) > 0 {
		channelNames, err := n.ci.GetLookupdTopicChannels(t.name, lookupdHTTPAddrs)
		if err != nil {
			n.logf(LOG_WARN, "failed to query nsqlookupd for channels to pre-create for topic %s - %s", t.name, err)
		}
		for _, channelName := range channelNames {
			//临时topic不需要预先创建，用到的时候再创建就行
			if strings.HasSuffix(channelName, "#ephemeral") {
				// we don't want to pre-create ephemeral channels
				// because there isn't a client connected
				continue
			}
			//预先创建一个channel，原因呢？为了让消息能够及时的入队.
			//比如，我这个nsq重启了，那么重启的这时刻，需要加载曾经的所有channel，以备每一个channel的消息不丢。不然只能等着对方create了，不方便
			t.getOrCreateChannel(channelName)
		}
	} else if len(n.getOpts().NSQLookupdTCPAddresses) > 0 {
		n.logf(LOG_ERROR, "no available nsqlookupd to query for channels to pre-create for topic %s", t.name)
	}

	t.Unlock()

	// NOTE: I would prefer for this to only happen in topic.GetChannel() but we're special
	// casing the code above so that we can control the locks such that it is impossible
	// for a message to be written to a (new) topic while we're looking up channels
	// from lookupd...
	//
	// update messagePump state
	select {
		//然后往管道channelUpdateChan里面塞入一个事件，通知topic的后台消息协程去处理channel的变动事件。
	case t.channelUpdateChan <- 1:
	case <-t.exitChan:
	}
	return t
}

// GetExistingTopic gets a topic only if it exists
func (n *NSQD) GetExistingTopic(topicName string) (*Topic, error) {
	n.RLock()
	defer n.RUnlock()
	topic, ok := n.topicMap[topicName]
	if !ok {
		return nil, errors.New("topic does not exist")
	}
	return topic, nil
}

// DeleteExistingTopic removes a topic only if it exists
func (n *NSQD) DeleteExistingTopic(topicName string) error {
	//删除topic的函数，分2步走，第一步先处理数据结构，最后再删除topicMap的映射
	n.RLock()
	topic, ok := n.topicMap[topicName]
	if !ok {
		n.RUnlock()
		return errors.New("topic does not exist")
	}
	n.RUnlock()

	// delete empties all channels and the topic itself before closing
	// (so that we dont leave any messages around)
	//
	// we do this before removing the topic from map below (with no lock)
	// so that any incoming writes will error and not create a new topic
	// to enforce ordering
	topic.Delete()

	n.Lock()
	//真正删除topic在topicMap中的位置
	delete(n.topicMap, topicName)
	n.Unlock()

	return nil
}

func (n *NSQD) Notify(v interface{}) {
	//用来通知notifyChan，有新的事件发生了，比如有topic或者channel增删， 这样在notifyChan放入一个元素后，会由lookupLoop 进行监听，后者会通知到lookupd进行处理。
	// since the in-memory metadata is incomplete,
	// should not persist metadata while loading it.
	// nsqd will call `PersistMetadata` it after loading
	persist := atomic.LoadInt32(&n.isLoading) == 0
	n.waitGroup.Wrap(func() {
		// by selecting on exitChan we guarantee that
		// we do not block exit, see issue #123
		select {
		case <-n.exitChan:
		case n.notifyChan <- v:
			if !persist {
				return
			}
			n.Lock()
			err := n.PersistMetadata()
			if err != nil {
				n.logf(LOG_ERROR, "failed to persist metadata - %s", err)
			}
			n.Unlock()
		}
	})
}

// channels returns a flat slice of all channels in all topics
func (n *NSQD) channels() []*Channel {
	var channels []*Channel
	n.RLock()
	for _, t := range n.topicMap {
		t.RLock()
		for _, c := range t.channelMap {
			channels = append(channels, c)
		}
		t.RUnlock()
	}
	n.RUnlock()
	return channels
}

// resizePool adjusts the size of the pool of queueScanWorker goroutines
//
// 	1 <= pool <= min(num * 0.25, QueueScanWorkerPoolMax)
//
func (n *NSQD) resizePool(num int, workCh chan *Channel, responseCh chan bool, closeCh chan int) {
	idealPoolSize := int(float64(num) * 0.25)
	if idealPoolSize < 1 {
		idealPoolSize = 1
	} else if idealPoolSize > n.getOpts().QueueScanWorkerPoolMax {
		idealPoolSize = n.getOpts().QueueScanWorkerPoolMax
	}
	for {
		if idealPoolSize == n.poolSize {
			break
		} else if idealPoolSize < n.poolSize {
			// contract
			closeCh <- 1
			n.poolSize--
		} else {
			// expand
			n.waitGroup.Wrap(func() {
				n.queueScanWorker(workCh, responseCh, closeCh)
			})
			n.poolSize++
		}
	}
}

// queueScanWorker receives work (in the form of a channel) from queueScanLoop
// and processes the deferred and in-flight queues
func (n *NSQD) queueScanWorker(workCh chan *Channel, responseCh chan bool, closeCh chan int) {
	for {
		select {
		case c := <-workCh:
			now := time.Now().UnixNano()
			dirty := false
			if c.processInFlightQueue(now) {
				dirty = true
			}
			if c.processDeferredQueue(now) {
				dirty = true
			}
			//有处理过消息
			responseCh <- dirty
		case <-closeCh:
			return
		}
	}
}

// queueScanLoop runs in a single goroutine to process in-flight and deferred
// priority queues. It manages a pool of queueScanWorker (configurable max of
// QueueScanWorkerPoolMax (default: 4)) that process channels concurrently.
//
// It copies Redis's probabilistic expiration algorithm: it wakes up every
// QueueScanInterval (default: 100ms) to select a random QueueScanSelectionCount
// (default: 20) channels from a locally cached list (refreshed every
// QueueScanRefreshInterval (default: 5s)).
//
// If either of the queues had work to do the channel is considered "dirty".
//
// If QueueScanDirtyPercent (default: 25%) of the selected channels were dirty,
// the loop continues without sleep.
func (n *NSQD) queueScanLoop() {
	//延迟投递和inflight队列扫描协程，动态创建协程处理
	workCh := make(chan *Channel, n.getOpts().QueueScanSelectionCount)
	responseCh := make(chan bool, n.getOpts().QueueScanSelectionCount)
	closeCh := make(chan int)

	workTicker := time.NewTicker(n.getOpts().QueueScanInterval)
	refreshTicker := time.NewTicker(n.getOpts().QueueScanRefreshInterval)

	channels := n.channels()
	n.resizePool(len(channels), workCh, responseCh, closeCh)

	for {
		select {
		case <-workTicker.C:
			if len(channels) == 0 {
				continue
			}
		case <-refreshTicker.C:
			channels = n.channels()
			n.resizePool(len(channels), workCh, responseCh, closeCh)
			continue
		case <-n.exitChan:
			goto exit
		}

		num := n.getOpts().QueueScanSelectionCount
		if num > len(channels) {
			num = len(channels)
		}

	loop:
		for _, i := range util.UniqRands(num, len(channels)) {
			workCh <- channels[i]
		}

		numDirty := 0
		for i := 0; i < num; i++ {
			if <-responseCh {
				numDirty++
			}
		}

		if float64(numDirty)/float64(num) > n.getOpts().QueueScanDirtyPercent {
			goto loop
		}
	}

exit:
	n.logf(LOG_INFO, "QUEUESCAN: closing")
	close(closeCh)
	workTicker.Stop()
	refreshTicker.Stop()
}

func buildTLSConfig(opts *Options) (*tls.Config, error) {
	var tlsConfig *tls.Config

	if opts.TLSCert == "" && opts.TLSKey == "" {
		return nil, nil
	}

	tlsClientAuthPolicy := tls.VerifyClientCertIfGiven

	cert, err := tls.LoadX509KeyPair(opts.TLSCert, opts.TLSKey)
	if err != nil {
		return nil, err
	}
	switch opts.TLSClientAuthPolicy {
	case "require":
		tlsClientAuthPolicy = tls.RequireAnyClientCert
	case "require-verify":
		tlsClientAuthPolicy = tls.RequireAndVerifyClientCert
	default:
		tlsClientAuthPolicy = tls.NoClientCert
	}

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tlsClientAuthPolicy,
		MinVersion:   opts.TLSMinVersion,
		MaxVersion:   tls.VersionTLS12, // enable TLS_FALLBACK_SCSV prior to Go 1.5: https://go-review.googlesource.com/#/c/1776/
	}

	if opts.TLSRootCAFile != "" {
		tlsCertPool := x509.NewCertPool()
		caCertFile, err := ioutil.ReadFile(opts.TLSRootCAFile)
		if err != nil {
			return nil, err
		}
		if !tlsCertPool.AppendCertsFromPEM(caCertFile) {
			return nil, errors.New("failed to append certificate to pool")
		}
		tlsConfig.ClientCAs = tlsCertPool
	}

	tlsConfig.BuildNameToCertificate()

	return tlsConfig, nil
}

func (n *NSQD) IsAuthEnabled() bool {
	return len(n.getOpts().AuthHTTPAddresses) != 0
}
