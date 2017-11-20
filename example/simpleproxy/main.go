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
	superProxy, _ := client.NewSuperProxy("zproxy.luminati.io", 22225, false, "lum-customer-bowang-zone-static", "uy2kopvtthos")
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
}

func (s *simpleSniffer) GetRequestWriter(uri []byte, header header.Header) io.Writer {
	fmt.Printf(`
************************
addr:%s
************************
request uri:%s
************************
content length:%d
************************
`,
		s.clientAddr, uri, header.ContentLength())
	return os.Stdout
}

func (s *simpleSniffer) GetResponseWriter(statusCode int, header header.Header) io.Writer {
	fmt.Printf(`
************************
addr:%s
************************
response status code:%d
************************
content length:%d
************************
`,
		s.clientAddr, statusCode, header.ContentLength())
	return os.Stdout
}
