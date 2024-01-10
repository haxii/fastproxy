package main

import (
	"bytes"
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

func main() {
	p := proxy.Proxy{
		ServerIdleDuration: time.Second * 30,
		HijackerPool:       &SimpleHijackerPool{},
	}

	panic(p.Serve("tcp", "0.0.0.0:8081"))
}

type SimpleHijackerPool struct {
	pool sync.Pool
}

func (p *SimpleHijackerPool) Get(clientAddr net.Addr, isHTTPS bool, host, port string) proxy.Hijacker {
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

func (p *SimpleHijackerPool) Put(h proxy.Hijacker) {
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
	fmt.Println("init called, passed", clientAddr.String(), host, port, "isHTTPS", isHTTPS)
	h.clientAddr = clientAddr
	h.host = host
	h.port = port
}

func (h *SimpleHijacker) RewriteHost() (newHost, newPort string) {
	fmt.Println("RewriteHost called, returned", h.host, h.port)
	return h.host, h.port
}

func (h *SimpleHijacker) OnConnect(header http.Header, rawHeader []byte) bool {
	fmt.Printf("OnConnect called with raw CONNECT header %s\n", strconv.Quote(string(rawHeader)))
	return true
}

func (h *SimpleHijacker) SSLBump() bool {
	// curl -k -x 0.0.0.0:8081 https://www.lumtest.com/echo.json
	shouldBump := strings.Contains(h.host, "lumtest.com")
	fmt.Println("SSLBump called, returned", shouldBump)
	return shouldBump
}

func (h *SimpleHijacker) RewriteTLSServerName(serverName string) string {
	fmt.Println("RewriteTLSServerName called, passed", serverName, "returned", serverName)
	return serverName
}

func (h *SimpleHijacker) BeforeRequest(method, path []byte, header http.Header, rawHeader []byte) (newPath, newRawHeader []byte) {
	newPath = path
	newRawHeader = rawHeader
	if bytes.Contains(rawHeader, []byte("no-proxy")) {
		// curl -H 'X-Fast-Proxy:no-proxy' -x 0.0.0.0:8081 http://httpbin.org/get
		h.superProxy = nil
	}

	fmt.Printf("BeforeRequest called   %s with path: %s, rawHeader: %s\n", method, path, strconv.Quote(string(rawHeader)))
	fmt.Printf("BeforeRequest returned %s with path: %s, rawHeader: %s\n", method, path, strconv.Quote(string(newRawHeader)))
	return bytes.Replace(newPath, []byte("get"), []byte("get?a=b&&cc=dd#ee"), -1),
		bytes.Replace(rawHeader, []byte("curl"), []byte("xurl"), -1)
}

func (h *SimpleHijacker) Resolve() net.IP {
	fmt.Println("Resolve called")
	return nil
}

func (h *SimpleHijacker) SuperProxy() *superproxy.SuperProxy {
	if h.superProxy != nil {
		fmt.Println("SuperProxy called, using super proxy", h.superProxy.HostWithPort())
	} else {
		fmt.Println("SuperProxy called, no super proxy used")
	}
	return h.superProxy
}

func (h *SimpleHijacker) Block() bool {
	shouldBlock := false
	// block evil sites
	if strings.Contains(h.host, "baidu") {
		shouldBlock = true
	}
	fmt.Println("Block called, returned", shouldBlock)
	return shouldBlock
}

func (h *SimpleHijacker) Dial() func(addr string) (net.Conn, error) {
	return func(addr string) (conn net.Conn, e error) {
		fmt.Println("Dial called")
		return transport.Dial(addr)
	}
}

func (h *SimpleHijacker) DialTLS() func(addr string, tlsConfig *tls.Config) (net.Conn, error) {
	return func(addr string, tlsConfig *tls.Config) (conn net.Conn, e error) {
		fmt.Println("DialTLS called")
		return transport.DialTLS(addr, tlsConfig)
	}
}

func (h *SimpleHijacker) OnRequest(path []byte, header http.Header, rawHeader []byte) io.WriteCloser {
	fmt.Printf("OnRequest called with path: %s, rawHeader: %s\n", path, strconv.Quote(string(rawHeader)))
	return nil
}

func (h *SimpleHijacker) OnResponse(statusLine http.ResponseLine, header http.Header, rawHeader []byte) io.WriteCloser {
	fmt.Println("OnResponse called")
	return nil
}

func (h *SimpleHijacker) HijackResponse() io.ReadCloser {
	fmt.Println("HijackResponse called")
	return nil
}

func (h *SimpleHijacker) AfterResponse(err error) {
	fmt.Println("AfterResponse called with error", err)
}

func (h *SimpleHijacker) OnFinish() {
	fmt.Println("OnFinish Called")
}
