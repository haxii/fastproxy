package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	nethttp "net/http"
	"net/url"
	"os"
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
	/*
		go func() {
			nethttp.HandleFunc("/https", func(w nethttp.ResponseWriter, req *nethttp.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte("Hello world!"))
			})
			serverCrt := `-----BEGIN CERTIFICATE-----
			MIICnzCCAggCCQDbF8N9hzgLKTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMC
			c2gxGjAYBgNVBAgMEXNoYW5naGFpIGluIENoaW5hMREwDwYDVQQHDAhzaGFuZ2hh
			aTEOMAwGA1UECgwFaGF4aWkxEDAOBgNVBAsMB3NlY3Rpb24xEjAQBgNVBAMMCWxv
			Y2FsaG9zdDEfMB0GCSqGSIb3DQEJARYQNDkzODg1NTk3QHFxLmNvbTAeFw0xODAz
			MDEwMzU4NDRaFw0xODAzMzEwMzU4NDRaMIGTMQswCQYDVQQGEwJzaDEaMBgGA1UE
			CAwRc2hhbmdoYWkgaW4gY2hpbmExETAPBgNVBAcMCHNoYW5naGFpMQ4wDAYDVQQK
			DAVoYXhpaTEQMA4GA1UECwwHc2VjdGlvbjESMBAGA1UEAwwJbG9jYWxob3N0MR8w
			HQYJKoZIhvcNAQkBFhA0OTM4ODU1OTdAcXEuY29tMIGfMA0GCSqGSIb3DQEBAQUA
			A4GNADCBiQKBgQCpavxAydg6qDcSHhzwcebD5v/o2yItY1a6cA8t4cd+8661TAQr
			//YRISpIwUZ7TOLVdmnMuyUzxGABZQ5iwiKDqbl5GLxB/f3NRWv5Cr8vT4izFNP0
			toIky5oEkDq/xBZvVnshBO6fpx1vulnow+3Y3WeriwVXvuQAQw5N8qod/QIDAQAB
			MA0GCSqGSIb3DQEBBQUAA4GBAG45K4B2N8lEeCimTyYuS9yGRQINMfdZksL2aDyq
			OL95JiCMKM1iFulom/fth3oxi1w95VRFaM4tO8qIBtKuFyWs8x1MMpTJlEamHFTe
			H1Id2JuKgDgi4AmxfKPjh+j+U6iNbMgjwo6scfaWcpteGK0FA5jn4cmMmlwhkjCA
			L/ib
			-----END CERTIFICATE-----
			`
			serverKey := `-----BEGIN RSA PRIVATE KEY-----
			MIICXQIBAAKBgQCpavxAydg6qDcSHhzwcebD5v/o2yItY1a6cA8t4cd+8661TAQr
			//YRISpIwUZ7TOLVdmnMuyUzxGABZQ5iwiKDqbl5GLxB/f3NRWv5Cr8vT4izFNP0
			toIky5oEkDq/xBZvVnshBO6fpx1vulnow+3Y3WeriwVXvuQAQw5N8qod/QIDAQAB
			AoGAdoPnDxOkdfQzAjOanwGvIyA3qZeSIxo5E5dMpxYozsB9WUpiKL2YT4dZ4yeB
			vMOecyGxBY1tivc3CgK9u4x/Q2RWQqG4n6d++RKKWEk5Znvi5H35gOcWbQgnOLfe
			VJKonqZwhDxWBjlIdKHRdlMY2qXY0rftDthas2zfLIWmSmkCQQDSX5zFhN1U3dAo
			cni5Qx3zBCGGw8aoFAH4bUPuvtb7LTnDb+xJDcxhC9pIy+5e3PcSa7cVN0DJpXEo
			QPMHp8jHAkEAziluenyR98PoJ2W/D8Cphuc5FvsRXOkGrcLdj397BZzTQhTrEPEr
			/qhn2uC4PqGBuS+GV1zgjTf4ocAz7TGHGwJBAKQ7pm0A07V8URQygZLIFepxMCdA
			UadHr14dFyqca8K9RNoRV1qU3hhpI2kvY5FFWdFUrCJw9zA060kso043q2MCQQCN
			bdDTiGeeoC+/70XeKZ5i5Ha+tCgaI+YoB/l0utCLbiVjPPRxn/E9dwwgFG9wz90t
			TFQN1LJbTp1rYW599q8nAkBDbXVZIDjwuL0SyUgnGJUKMILk0aanNE2E885wyuZm
			PAnrpRqdDz9eQITxrUgW8vJKxBH6hNNGcMz9VHUgnsSE
			-----END RSA PRIVATE KEY-----
			`
			f, err := os.Create(".server.crt")
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			f.Write([]byte(serverCrt))
			f.Close()

			f, err = os.Create(".server.key")
			f.Write([]byte(serverKey))
			f.Close()

			err = nethttp.ListenAndServeTLS(":443", ".server.crt", ".server.key", nil)
			if err != nil {
				slog.Fatal("ListenAndServe: ", err)
			}
		}()*/
	go func() {
		superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 443, superproxy.ProxyTypeHTTPS, "", "", false, "")
		ln, err := net.Listen("tcp4", "0.0.0.0:5060")
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
					return superProxy
				},
				HijackerPool: &SimpleHijackerPool{},
			},
		}
		if err := proxy.Serve(ln, 30*time.Second); err != nil {
			panic(err)
		}
	}()
	go func() {
		superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 9099, superproxy.ProxyTypeSOCKS5, "", "", false, "")
		ln, err := net.Listen("tcp4", "0.0.0.0:5030")
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
					return superProxy
				},
				HijackerPool: &SimpleHijackerPool{},
			},
		}
		if err := proxy.Serve(ln, 30*time.Second); err != nil {
			panic(err)
		}
	}()
	go func() {
		superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 5080, superproxy.ProxyTypeHTTP, "", "", false, "")
		ln, err := net.Listen("tcp4", "0.0.0.0:5040")
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
					return superProxy
				},
				HijackerPool: &SimpleHijackerPool{},
			},
		}
		if err := proxy.Serve(ln, 30*time.Second); err != nil {
			panic(err)
		}
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
	tesHTTPRequest(t)
	//testHTTPSRequest(t)
	testHTTPSuperProxyWithHTTPRequest(t)
	//testHTTPSuperProxyWithHTTPSRequest(t)
	//testHTTPSSuperProxyWithHTTPRequest(t)
	//testHTTPSSuperProxyWithHTTPSRequest(t)
	testSocks5SuperProxyyWithHTTPRequest(t)
	//testSocks5SuperProxyWithHTTPSRequest(t)
	defer os.Remove(".server.crt")
	defer os.Remove(".server.key")
}

func tesHTTPRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5050))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy: proxy,
	}
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

func testHTTPSRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5050))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy:           proxy,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := nethttp.NewRequest("GET", "https://127.0.0.1:443/https", nil)
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
func testHTTPSuperProxyWithHTTPRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5040))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy:           proxy,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := nethttp.NewRequest("GET", "http://127.0.0.1:9990", nil)
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
func testHTTPSuperProxyWithHTTPSRequest(t *testing.T) {

}
func testHTTPSSuperProxyWithHTTPRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5060))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy:           proxy,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := nethttp.NewRequest("GET", "http://127.0.0.1:9990", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Printf(string(body))
	if string(body) != "Hello world!\r\n" {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

func testHTTPSSuperProxyWithHTTPSRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5060))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy:           proxy,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := nethttp.NewRequest("GET", "http://127.0.0.1:443", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Printf(string(body))
	if string(body) != "Hello world!\r\n" {
		t.Fatal("An error occurred: proxy can't send request")
	}
}
func testSocks5SuperProxyyWithHTTPRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5030))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy:           proxy,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := nethttp.NewRequest("GET", "http://127.0.0.1:9990", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Printf(string(body))
	if string(body) != "Hello world!\r\n" {
		t.Fatal("An error occurred: proxy can't send request")
	}
}
func testSocks5SuperProxyWithHTTPSRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5030))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy:           proxy,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := nethttp.NewRequest("GET", "https://127.0.0.1:443", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Printf(string(body))
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
