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

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/hijack"
	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/proxy/proxy"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/usage"
	"github.com/haxii/log"
)

func main() {
	ln, err := net.Listen("tcp4", "0.0.0.0:8080")
	if err != nil {
		return
	}
	superProxy, _ := superproxy.NewSuperProxy("0.0.0.0", 8081, superproxy.ProxyTypeHTTP, "", "", true)
	superProxy.SetMaxConcurrency(20)

	proxy := proxy.Proxy{
		BufioPool:   &bufiopool.Pool{},
		Client:      client.Client{},
		ProxyLogger: &log.DefaultLogger{},
		Handler: proxy.Handler{
			ShouldAllowConnection: func(conn net.Addr) bool {
				fmt.Printf("allowed connection from %s\n", conn.String())
				return true
			},
			ShouldDecryptHost: func(hostWithPort string) bool {
				return true
			},
			URLProxy: func(hostWithPort string, uri []byte) *superproxy.SuperProxy {
				if strings.Contains(hostWithPort, "lumtest") {
					return nil
				}
				if len(uri) == 0 {
					//this is a connections should not decrypt
					fmt.Println(hostWithPort)
				}
				return superProxy
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
		Usage: usage.NewProxyUsage(),
	}

	if err := proxy.Serve(ln, 30*time.Second); err != nil {
		panic(err)
	}
}

//SimpleHijackerPool implements the HijackerPool based on simpleHijacker & sync.Pool
type SimpleHijackerPool struct {
	pool sync.Pool
}

//Get get a simple hijacker from pool
func (p *SimpleHijackerPool) Get(clientAddr net.Addr,
	targetHost string, method, path []byte) hijack.Hijacker {
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
func (p *SimpleHijackerPool) Put(s hijack.Hijacker) {
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
		return strings.NewReader("HTTP/1.1 501 Response Hijacked\r\n\r\n")
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
