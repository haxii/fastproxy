package proxy

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	nethttp "net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/hijack"
	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/log"
)

func TestProxyServe(t *testing.T) {
	go func() {
		ln, err := net.Listen("tcp4", "0.0.0.0:5050")
		if err != nil {
			return
		}
		proxy := Proxy{
			BufioPool:   &bufiopool.Pool{},
			Client:      client.Client{},
			ProxyLogger: &log.DefaultLogger{},
			Handler: Handler{
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
					return nil
				},
				HijackerPool: &SimpleHijackerPool{},
			},
		}
		if err := proxy.Serve(ln, 30*time.Second); err != nil {
			panic(err)
		}
	}()

	conn, err := net.Dial("tcp4", "0.0.0.0:5050")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\n\r\n")
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if status != "HTTP/1.1 400 Bad Request\r\n" {
		t.Fatalf("an error occurred when send get request")
	}
}

func TestFastProxyAsProxyServe(t *testing.T) {
	go func() {
		nethttp.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			fmt.Fprintf(w, "Hello world%s!\r\n", r.URL.Path[1:])
		})
		nethttp.ListenAndServe(":9990", nil)
	}()
	go func() {
		ln, err := net.Listen("tcp4", "0.0.0.0:5050")
		if err != nil {
			return
		}
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		proxy := Proxy{
			BufioPool:   &bufiopool.Pool{},
			Client:      client.Client{},
			ProxyLogger: &log.DefaultLogger{},
			Handler: Handler{
				ShouldAllowConnection: func(conn net.Addr) bool {
					return true
				},
				ShouldDecryptHost: func(hostWithPort string) bool {
					return true
				},
				URLProxy: func(hostWithPort string, uri []byte) *superproxy.SuperProxy {
					return nil
				},
				HijackerPool: &SimpleHijackerPool{},
			},
		}
		if err := proxy.Serve(ln, 30*time.Second); err != nil {
			panic(err)
		}
	}()
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5050))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{Proxy: proxy}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := nethttp.NewRequest("GET", "http://localhost:9990", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if string(body) != "Hello world!\r\n" {
		t.Fatal("An error occurred: proxy can't send request")
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
	return h
}

//Put puts a simple hijacker back to pool
func (p *SimpleHijackerPool) Put(s hijack.Hijacker) {
	p.pool.Put(s)
}

type simpleHijacker struct{}

func (s *simpleHijacker) OnRequest(header http.Header, rawHeader []byte) io.Writer {
	return nil
}

func (s *simpleHijacker) HijackResponse() io.Reader {
	return nil
}

func (s *simpleHijacker) OnResponse(respLine http.ResponseLine,
	header http.Header, rawHeader []byte) io.Writer {
	return nil
}
