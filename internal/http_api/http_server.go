package http_api

import (
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/kulv2012/nsq/internal/lg"
)

type logWriter struct {
	logf lg.AppLogFunc
}

func (l logWriter) Write(p []byte) (int, error) {
	l.logf(lg.WARN, "%s", string(p))
	return len(p), nil
}

//http的包装函数，传入tcp连接句柄，和http处理句柄HTTPServer，以及协议名称proto http、https
//tcp协议的处理函数是TCPServer，相对简单，就是个死循环不断接受连接，然后创建协程进行处理
func Serve(listener net.Listener, handler http.Handler, proto string, logf lg.AppLogFunc) {
	logf(lg.INFO, "%s: listening on %s", proto, listener.Addr())

	//创建一个http的句柄server指针，传入handler
	server := &http.Server{
		Handler:  handler,
		ErrorLog: log.New(logWriter{logf}, "", 0),
	}
	//开启服务，这样如果有连接到来，会不断调用到handler上进行路由
	//下面函数会一直循环执行下去，不会立即返回退出,知道最后主动退出程序为止
	err := server.Serve(listener)
	// theres no direct way to detect this error because it is not exposed
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		logf(lg.ERROR, "http.Serve() - %s", err)
	}

	logf(lg.INFO, "%s: closing %s", proto, listener.Addr())
}
