package main

import (
	"bytes"
	"crypto/tls"
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
	"github.com/haxii/fastproxy/transport"
	"github.com/haxii/log"
)

var superProxy1, superProxy2 *superproxy.SuperProxy

func main() {
	superProxy1, _ = superproxy.NewSuperProxy("a.b", 1080, superproxy.ProxyTypeHTTP, "", "", "")
	superProxy2, _ = superproxy.NewSuperProxy("a.b", 6050, superproxy.ProxyTypeHTTP, "", "", "")
	superProxy1.SetMaxConcurrency(20)

	proxy := proxy.Proxy{
		Logger: &log.DefaultLogger{},
		Handler: proxy.Handler{
			Dial: func(addr string) (conn net.Conn, e error) {
				return transport.Dial(addr)
			},
			DialTLS: func(addr string, tlsConfig *tls.Config) (conn net.Conn, e error) {
				return transport.DialTLS(addr, tlsConfig)
			},
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
				return superProxy1
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

func (s *simpleHijacker) HijackRequest(header http.Header, rawHeader []byte, superProxy **superproxy.SuperProxy) []byte {
	if bytes.Contains(rawHeader, []byte("curl")) {
		fmt.Printf("***\n\n\n%s\n\n\n", rawHeader)
		// all curl requests using super proxy2
		*superProxy = superProxy2
		// replace curl as burl in user-agent
		return bytes.Replace(rawHeader, []byte("curl"), []byte("burl"), -1)
	}
	return nil
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
