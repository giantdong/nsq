package nsqlookupd

import (
	"io"
	"net"

	"github.com/kulv2012/nsq/internal/protocol"
)

type tcpServer struct {
	ctx *Context
}

func (p *tcpServer) Handle(clientConn net.Conn) {
	//如果有客户端连接，上层会创建一个协程，调用这里.
	//本函数判断协议版本，之后就基本就调用了LookupProtocolV1::IOLoop
	p.ctx.nsqlookupd.logf(LOG_INFO, "TCP: new client(%s)", clientConn.RemoteAddr())

	// The client should initialize itself by sending a 4 byte sequence indicating
	// the version of the protocol that it intends to communicate, this will allow us
	// to gracefully upgrade the protocol away from text/line oriented to whatever...
	buf := make([]byte, 4)
	_, err := io.ReadFull(clientConn, buf)
	if err != nil {
		p.ctx.nsqlookupd.logf(LOG_ERROR, "failed to read protocol version - %s", err)
		clientConn.Close()
		return
	}
	protocolMagic := string(buf)

	p.ctx.nsqlookupd.logf(LOG_INFO, "CLIENT(%s): desired protocol magic '%s'",
		clientConn.RemoteAddr(), protocolMagic)

	var prot protocol.Protocol
	switch protocolMagic {
	case "  V1":
		prot = &LookupProtocolV1{ctx: p.ctx}
	default:
		protocol.SendResponse(clientConn, []byte("E_BAD_PROTOCOL"))
		clientConn.Close()
		p.ctx.nsqlookupd.logf(LOG_ERROR, "client(%s) bad protocol magic '%s'",
			clientConn.RemoteAddr(), protocolMagic)
		return
	}

	err = prot.IOLoop(clientConn)
	if err != nil {
		p.ctx.nsqlookupd.logf(LOG_ERROR, "client(%s) - %s", clientConn.RemoteAddr(), err)
		return
	}
}
