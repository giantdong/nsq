package protocol

import (
	"net"
	"runtime"
	"strings"

	"github.com/kulv2012/nsq/internal/lg"
)

type TCPHandler interface {
	Handle(net.Conn)
}

//Listener是一个监听的net.Listen类，TCPHandler 是一个tcpServer 类，用来处理事件的
//TCPServer 用来进行accept然后就创立一个go协程调用handler的Handle函数处理后面的逻辑
func TCPServer(listener net.Listener, handler TCPHandler, logf lg.AppLogFunc) {
	logf(lg.INFO, "TCP: listening on %s", listener.Addr())

	for {
		//等待接受一个客户端连接
		clientConn, err := listener.Accept()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				logf(lg.WARN, "temporary Accept() failure - %s", err)
				runtime.Gosched()
				continue
			}
			// theres no direct way to detect this error because it is not exposed
			if !strings.Contains(err.Error(), "use of closed network connection") {
				logf(lg.ERROR, "listener.Accept() - %s", err)
			}
			break
		}
		//在协程中处理这一个客户端请求, 直至结束连接. 所以go是一个客户端连接一个协程处理
		go handler.Handle(clientConn)
	}

	logf(lg.INFO, "TCP: closing %s", listener.Addr())
}
