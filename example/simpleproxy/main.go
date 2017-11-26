package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/hijack"
	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/log"
	"github.com/haxii/fastproxy/proxy/proxy"
	"github.com/haxii/fastproxy/superproxy"
)

func main() {
	ln, err := net.Listen("tcp4", "0.0.0.0:8080")
	if err != nil {
		return
	}
	superProxy, _ := superproxy.NewSuperProxy("10.1.1.9", 8118, false, "", "")
	proxy := proxy.Proxy{
		BufioPool:   &bufiopool.Pool{},
		Client:      client.Client{},
		ProxyLogger: &log.DefaultLogger{},
		Handler: proxy.Handler{
			HijackerPool: &SimpleHijackerPool{},
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
		},
	}
	if err := proxy.Serve(ln); err != nil {
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
addr:%s, host:%s
************************
%s %s
************************
content length:%d
************************
%s
************************
`,
		s.clientAddr, s.targetHost, s.method, s.path,
		header.ContentLength(), rawHeader)
	return os.Stdout
}

func (s *simpleHijacker) HijackResponse() *bufio.Reader {
	if strings.Contains(s.targetHost, "douban") {
		reader := strings.NewReader("HTTP/1.1 501 Response Hijacked\r\n\r\n")
		return bufio.NewReader(reader)
	}
	return nil
}

func (s *simpleHijacker) OnResponse(statusCode int,
	header http.Header, rawHeader []byte) io.Writer {
	fmt.Printf(`
************************
addr:%s, host:%s
************************
%s %s
************************
status code:%d
************************
content length:%d
************************
%s
************************
`,
		s.clientAddr, s.targetHost, s.method, s.path,
		statusCode, header.ContentLength(), rawHeader)
	return os.Stdout
}
