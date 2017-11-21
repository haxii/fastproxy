package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/header"
	"github.com/haxii/fastproxy/log"
	"github.com/haxii/fastproxy/proxy"
)

func main() {
	ln, err := net.Listen("tcp4", "0.0.0.0:8080")
	if err != nil {
		return
	}
	superProxy, _ := client.NewSuperProxy("proxy.address", 8080, false, "user", "pass")
	proxy := proxy.Proxy{
		BufioPool:   &bufiopool.Pool{},
		Client:      client.Client{},
		ProxyLogger: &log.DefaultLogger{},
		SnifferPool: &SimpleSnifferPool{},
		Handler: proxy.Handler{
			URLProxy: func(uri []byte) *client.SuperProxy {
				return superProxy
			},
		},
	}
	if err := proxy.Serve(ln); err != nil {
		panic(err)
	}
}

//SimpleSnifferPool implements the SnifferPool based on simpleSniffer & sync.Pool
type SimpleSnifferPool struct {
	pool sync.Pool
}

//Get get a simple sniffer from pool
func (p *SimpleSnifferPool) Get(addr net.Addr) proxy.Sniffer {
	v := p.pool.Get()
	if v == nil {
		sniffer := &simpleSniffer{clientAddr: addr.String()}
		return sniffer
	}
	sniffer := v.(*simpleSniffer)
	sniffer.clientAddr = addr.String()
	return sniffer
}

//Put puts a simple sniffer back to pool
func (p *SimpleSnifferPool) Put(s proxy.Sniffer) {
	p.pool.Put(s)
}

type simpleSniffer struct {
	clientAddr string
	host       string
}

func (s *simpleSniffer) GetRequestWriter(host string, method, path []byte,
	header header.Header, rawHeader []byte) io.Writer {
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

func (s *simpleSniffer) GetResponseWriter(statusCode int,
	header header.Header, rawHeader []byte) io.Writer {
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
