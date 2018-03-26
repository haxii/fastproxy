package main

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/proxy"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/uri"
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
			ShouldDecryptHost: func(hostWithPort string) bool {
				return false
			},
			URLProxy: func(hostInfo *uri.HostInfo, uri []byte) *superproxy.SuperProxy {
				return nil
			},
			HijackerPool: &SimpleHijackerPool{},
			LookupIP: func(domain string) net.IP {
				ips, err := net.LookupIP(domain)
				if err != nil || len(ips) == 0 {
					return nil
				}
				randInt := rand.Intn(len(ips))
				return ips[randInt]
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
	targetHost string, method, path []byte) proxy.Hijacker {
	v := p.pool.Get()
	var h *simpleHijacker
	if v == nil {
		h = &simpleHijacker{}
	} else {
		h = v.(*simpleHijacker)
	}
	h.Set(clientAddr, targetHost, method, path)
	return h
}

//Put puts a simple hijacker back to pool
func (p *SimpleHijackerPool) Put(s proxy.Hijacker) {
	p.pool.Put(s)
}

type simpleHijacker struct {
	clientAddr, targetHost string
	method, path           []byte
}

func (s *simpleHijacker) Set(clientAddr net.Addr,
	host string, method, path []byte) {
	s.clientAddr = clientAddr.String()
	s.targetHost = host
	s.method = method
	s.path = path
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
