package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/proxy"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/log"
)

func main() {
	superProxy, _ := superproxy.NewSuperProxy("a.b", 1080, superproxy.ProxyTypeHTTP, "", "", "")
	superProxy.SetMaxConcurrency(20)

	proxy := proxy.Proxy{
		Logger: &log.DefaultLogger{},
		Handler: proxy.Handler{
			ShouldAllowConnection: func(conn net.Addr) bool {
				fmt.Printf("allowed connection from %s\n", conn.String())
				return true
			},
			ShouldDecryptHost: func(userdata *proxy.UserData, hostWithPort string) bool {
				return false
			},
			RewriteURL: func(userdata *proxy.UserData, hostWithPort string) string {
				return hostWithPort
			},
			URLProxy: func(userdata *proxy.UserData, hostWithPort string, uri []byte) *superproxy.SuperProxy {
				return superProxy
			},
			HijackerPool: &SimpleHijackerPool{},
			LookupIP: func(userdata *proxy.UserData, domain string) net.IP {
				return nil
			},
		},
		ServerIdleDuration: time.Second * 30,
	}

	panic(proxy.Serve("tcp", "0.0.0.0:8081"))
}

//SimpleHijackerPool implements the HijackerPool based on simpleHijacker & sync.Pool
type SimpleHijackerPool struct {
	pool sync.Pool
}

//Get get a simple hijacker from pool
func (p *SimpleHijackerPool) Get(clientAddr net.Addr,
	targetHost string, method, path []byte, userdata *proxy.UserData) proxy.Hijacker {
	v := p.pool.Get()
	var h *simpleHijacker
	if v == nil {
		h = &simpleHijacker{}
	} else {
		h = v.(*simpleHijacker)
	}
	h.Set(clientAddr, targetHost, method, path, userdata)
	return h
}

//Put puts a simple hijacker back to pool
func (p *SimpleHijackerPool) Put(s proxy.Hijacker) {
	p.pool.Put(s)
}

type simpleHijacker struct {
	clientAddr, targetHost string
	method, path           []byte
	userdata               *proxy.UserData
}

func (s *simpleHijacker) Set(clientAddr net.Addr,
	host string, method, path []byte, userdata *proxy.UserData) {
	s.clientAddr = clientAddr.String()
	s.targetHost = host
	s.method = method
	s.path = path
	s.userdata = userdata
}

func (s *simpleHijacker) OnRequest(header http.Header, rawHeader []byte) io.Writer {
	fmt.Printf(`
	************************
	addr: %s, host: %s
	************************
	%s %s
	************************
	content length: %d
	************************
	%s
	************************
	`,
		s.clientAddr, s.targetHost, s.method, s.path,
		header.ContentLength(), rawHeader)
	return os.Stdout
}

func (s *simpleHijacker) HijackResponse() io.Reader {
	if strings.Contains(s.targetHost, "douban") {
		return strings.NewReader("HTTP/1.1 501 Response Hijacked\r\nContent-Length:0\r\n\r\n")
	}
	return nil
}

func (s *simpleHijacker) OnResponse(respLine http.ResponseLine,
	header http.Header, rawHeader []byte) io.Writer {
	fmt.Printf(`
	************************
	addr: %s, host: %s
	************************
	%s %s
	************************
	%s %d %s
	************************
	content length: %d
	content type: %s
	************************
	%s
	************************
	`,
		s.clientAddr, s.targetHost, s.method, s.path,
		respLine.GetProtocol(), respLine.GetStatusCode(), respLine.GetStatusMessage(),
		header.ContentLength(), header.ContentType(), rawHeader)
	return os.Stdout
}
