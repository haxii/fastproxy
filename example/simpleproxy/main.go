package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/hijack"
	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/log"
	"github.com/haxii/fastproxy/proxy"
	"github.com/haxii/fastproxy/superproxy"
)

func main() {
	ln, err := net.Listen("tcp4", "0.0.0.0:8080")
	if err != nil {
		return
	}
	superProxy, _ := superproxy.NewSuperProxy("10.1.1.9", 8118, false, "", "")
	proxy := proxy.Proxy{
		BufioPool:    &bufiopool.Pool{},
		Client:       client.Client{},
		ProxyLogger:  &log.DefaultLogger{},
		HijackerPool: &SimpleHijackerPool{},
		Handler: proxy.Handler{
			ShouldDecryptHost: func(hostWithPort string) bool {
				return false
			},
			URLProxy: func(hostWithPort string, uri []byte) *superproxy.SuperProxy {
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
func (p *SimpleHijackerPool) Get(addr net.Addr) hijack.Hijacker {
	v := p.pool.Get()
	if v == nil {
		hijacker := &simpleHijacker{clientAddr: addr.String()}
		return hijacker
	}
	hijacker := v.(*simpleHijacker)
	hijacker.clientAddr = addr.String()
	return hijacker
}

//Put puts a simple hijacker back to pool
func (p *SimpleHijackerPool) Put(s hijack.Hijacker) {
	p.pool.Put(s)
}

type simpleHijacker struct {
	clientAddr string
	host       string
}

func (s *simpleHijacker) OnRequest(host string, method, path []byte,
	header http.Header, rawHeader []byte) io.Writer {
	s.host = host
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
		s.clientAddr, s.host, method, path, header.ContentLength(), rawHeader)
	return os.Stdout
}

func (s *simpleHijacker) HijackResponse() io.Reader {
	return nil
}

func (s *simpleHijacker) OnResponse(statusCode int,
	header http.Header, rawHeader []byte) io.Writer {
	fmt.Printf(`
************************
addr:%s, host:%s
************************
status code:%d
************************
content length:%d
************************
%s
************************
`,
		s.clientAddr, s.host, statusCode, header.ContentLength(), rawHeader)
	return os.Stdout
}
