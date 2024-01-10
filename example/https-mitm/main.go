package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/proxy"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/transport"
)

// this example generates a Pintrest proxy and cracks the images request
// plug this proxy into chrome and open the website, you can see a few
// connect logs and lots of on request logs for image

func main() {
	p := proxy.Proxy{
		ServerIdleDuration: time.Second * 30,
		HijackerPool:       &mitmHijackerPool{},
	}

	panic(p.Serve("tcp", "0.0.0.0:8081"))
}

type mitmHijackerPool struct {
	pool sync.Pool
}

func (p *mitmHijackerPool) Get(clientAddr net.Addr, isHTTPS bool, host, port string) proxy.Hijacker {
	v := p.pool.Get()
	var h *SimpleHijacker
	if v == nil {
		h = &SimpleHijacker{}
	} else {
		h = v.(*SimpleHijacker)
	}
	h.init(clientAddr, isHTTPS, host, port)
	return h
}

func (p *mitmHijackerPool) Put(h proxy.Hijacker) {
	hijacker := h.(*SimpleHijacker)
	hijacker.OnFinish()
	p.pool.Put(h)
}

type SimpleHijacker struct {
	clientAddr net.Addr
	host, port string
	isHTTPS    bool
	superProxy *superproxy.SuperProxy
}

func (h *SimpleHijacker) init(clientAddr net.Addr, isHTTPS bool, host, port string) {
	if strings.Contains(host, "pinimg.com") {
		//fmt.Println("init called, passed", clientAddr.String(), host, port, "isHTTPS", isHTTPS)
	}
	h.clientAddr = clientAddr
	h.host = host
	h.port = port
	h.superProxy = nil
}

func (h *SimpleHijacker) RewriteHost() (newHost, newPort string) {
	return h.host, h.port
}

func (h *SimpleHijacker) OnConnect(header http.Header, rawHeader []byte) bool {
	if strings.Contains(h.host, "pinimg.com") {
		fmt.Printf("OnConnect called with raw CONNECT header %s\n", strconv.Quote(string(rawHeader)))
	}
	return true
}

func (h *SimpleHijacker) SSLBump() bool {
	if strings.Contains(h.host, "pinimg.com") {
		return true
	}
	return false
}

func (h *SimpleHijacker) RewriteTLSServerName(serverName string) string {
	return serverName
}

func (h *SimpleHijacker) BeforeRequest(method, path []byte, header http.Header, rawHeader []byte) (newPath, newRawHeader []byte) {
	return path, rawHeader
}

func (h *SimpleHijacker) Resolve() net.IP {
	return nil
}

func (h *SimpleHijacker) SuperProxy() *superproxy.SuperProxy {
	return h.superProxy
}

func (h *SimpleHijacker) Block() bool {
	return false
}

func (h *SimpleHijacker) Dial() func(addr string) (net.Conn, error) {
	return func(addr string) (conn net.Conn, e error) { return transport.Dial(addr) }
}

func (h *SimpleHijacker) DialTLS() func(addr string, tlsConfig *tls.Config) (net.Conn, error) {
	return func(addr string, tlsConfig *tls.Config) (conn net.Conn, e error) {
		return transport.DialTLS(addr, tlsConfig)
	}
}

func (h *SimpleHijacker) OnRequest(path []byte, header http.Header, rawHeader []byte) io.WriteCloser {
	if strings.Contains(h.host, "pinimg.com") {
		fmt.Printf("OnRequest called with path: %s\n", path)
	}
	return nil
}

func (h *SimpleHijacker) OnResponse(statusLine http.ResponseLine, header http.Header, rawHeader []byte) io.WriteCloser {
	return nil
}

func (h *SimpleHijacker) AfterResponse(err error) {
}

func (h *SimpleHijacker) HijackResponse() io.ReadCloser { return nil }

func (h *SimpleHijacker) OnFinish() {
	if strings.Contains(h.host, "pinimg.com") {
		fmt.Println("OnFinish Called")
	}
}
