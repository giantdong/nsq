package nsqlookupd

import (
	"log"
	"net"
	"os"
	"sync"

	"github.com/kulv2012/nsq/internal/http_api"
	"github.com/kulv2012/nsq/internal/lg"
	"github.com/kulv2012/nsq/internal/protocol"
	"github.com/kulv2012/nsq/internal/util"
	"github.com/kulv2012/nsq/internal/version"
)

type NSQLookupd struct {
	sync.RWMutex
	opts         *Options
	tcpListener  net.Listener
	httpListener net.Listener
	waitGroup    util.WaitGroupWrapper
	DB           *RegistrationDB
}

func New(opts *Options) *NSQLookupd {
	//初始化日志，new一个NSQLookupd返回，没干别的
	if opts.Logger == nil {
		opts.Logger = log.New(os.Stderr, opts.LogPrefix, log.Ldate|log.Ltime|log.Lmicroseconds)
	}
	n := &NSQLookupd{
		opts: opts,
		DB:   NewRegistrationDB(),
	}

	var err error
	opts.logLevel, err = lg.ParseLogLevel(opts.LogLevel, opts.Verbose)
	if err != nil {
		n.logf(LOG_FATAL, "%s", err)
		os.Exit(1)
	}

	n.logf(LOG_INFO, version.String("nsqlookupd"))
	return n
}

func (l *NSQLookupd) Main() {
	//apps/nsqlookupd/nsqlookupd.go 调用这里
	ctx := &Context{l}

	tcpListener, err := net.Listen("tcp", l.opts.TCPAddress)
	if err != nil {
		l.logf(LOG_FATAL, "listen (%s) failed - %s", l.opts.TCPAddress, err)
		os.Exit(1)
	}
	l.Lock()
	l.tcpListener = tcpListener
	l.Unlock()
	//tcp协议处理函数其实是LookupProtocolV1::IOLoop,  支持IDENTIFY， REGISTER, UNREGISTER 操作
	tcpServer := &tcpServer{ctx: ctx}
	l.waitGroup.Wrap(func() {
		protocol.TCPServer(tcpListener, tcpServer, l.logf)
	})

	httpListener, err := net.Listen("tcp", l.opts.HTTPAddress)
	if err != nil {
		l.logf(LOG_FATAL, "listen (%s) failed - %s", l.opts.HTTPAddress, err)
		os.Exit(1)
	}
	l.Lock()
	l.httpListener = httpListener
	l.Unlock()
	//http协议要复杂很多
	httpServer := newHTTPServer(ctx)
	l.waitGroup.Wrap(func() {
		http_api.Serve(httpListener, httpServer, "HTTP", l.logf)
	})
}

func (l *NSQLookupd) RealTCPAddr() *net.TCPAddr {
	l.RLock()
	defer l.RUnlock()
	return l.tcpListener.Addr().(*net.TCPAddr)
}

func (l *NSQLookupd) RealHTTPAddr() *net.TCPAddr {
	l.RLock()
	defer l.RUnlock()
	return l.httpListener.Addr().(*net.TCPAddr)
}

func (l *NSQLookupd) Exit() {
	if l.tcpListener != nil {
		l.tcpListener.Close()
	}

	if l.httpListener != nil {
		l.httpListener.Close()
	}
	l.waitGroup.Wait()
}
