package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	slog "log"
	"net"
	nethttp "net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fastfork/fastproxy/bytebufferpool"
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

//TestFastProxyAsProxyServe test fast proxy as http https socks5 proxy
func TestFastProxyAsProxyServe(t *testing.T) {
	go func() {
		nethttp.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			fmt.Fprintf(w, "Hello world%s!", r.URL.Path[1:])
		})
		nethttp.ListenAndServe(":9990", nil)
	}()

	go func() {
		nethttp.HandleFunc("/https", func(w nethttp.ResponseWriter, req *nethttp.Request) {
			w.WriteHeader(200)
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

		err = nethttp.ListenAndServeTLS(":444", ".server.crt", ".server.key", nil)
		if err != nil {
			slog.Fatal("ListenAndServe: ", err)
		}
	}()
	go func() {
		superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 8888, superproxy.ProxyTypeHTTPS, "", "", false, "../proxy/proxy/.server.crt")
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
					return false
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
					return false
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
		superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 3128, superproxy.ProxyTypeHTTP, "", "", false, "")
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
					return false
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
	testHTTPSRequest(t)
	testHTTPSuperProxyWithHTTPRequest(t)
	testHTTPSuperProxyWithHTTPSRequest(t)
	testHTTPSSuperProxyWithHTTPRequest(t)
	testHTTPSSuperProxyWithHTTPSRequest(t)
	testSocks5SuperProxyyWithHTTPRequest(t)
	testSocks5SuperProxyWithHTTPSRequest(t)
	testDNSAnalysis(t)

	testBigHeader(t)

	testUsingProxyHijackAndURLSendToDifferProxy(t)
	defer os.Remove(".server.crt")
	defer os.Remove(".server.key")
}

//test send http request with fastproxy
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
	if string(body) != "Hello world!" {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

// test send https request with fastproxy
func testHTTPSRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5050))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy: proxy,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost"},
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	req, err := nethttp.NewRequest("GET", "https://127.0.0.1:444", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if string(body) != "Hello world!" {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

// test send http request with http superproxy
func testHTTPSuperProxyWithHTTPRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5040))
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
	req, err := nethttp.NewRequest("GET", "http://127.0.0.1:9990", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if string(body) != "Hello world!" {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

// test send https request with http superproxy
func testHTTPSuperProxyWithHTTPSRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5040))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy: proxy,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
		},
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := nethttp.NewRequest("GET", "https://127.0.0.1:444", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if string(body) != "Hello world!" {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

// test send http request with https superproxy
func testHTTPSSuperProxyWithHTTPRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("https://%s:%d", "127.0.0.1", 5060))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy: proxy,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
		},
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
	fmt.Println(string(body))
	if string(body) != "Hello world!" {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

// test send https request with https superproxy
func testHTTPSSuperProxyWithHTTPSRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5060))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy: proxy,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost"},
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := nethttp.NewRequest("GET", "http://127.0.0.1:444", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if string(body) != "Hello world!" {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

// test send http request with socks5 superproxy
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
	if string(body) != "Hello world!" {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

// test send https request with socks5 superproxy
func testSocks5SuperProxyWithHTTPSRequest(t *testing.T) {
	proxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 5030))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy: proxy,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true,
			ServerName: "localhost"},
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := nethttp.NewRequest("GET", "https://127.0.0.1:444", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	if string(body) != "Hello world!" {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

// test local DNS analysis by dnsmasq
func testDNSAnalysis(t *testing.T) {
	ns, err := net.LookupHost("localhost")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	isExist := false
	for _, n := range ns {
		if n == "127.0.0.1" {
			isExist = true
		}
	}
	if !isExist {
		t.Fatalf("Local DNS analysis is wrong")
	}
}

// test read timeout and max keep alive duration
func testReadTimeoutAndMaxKeepaliveDuration(t *testing.T) {
	go func() {
		ln, err := net.Listen("tcp4", "0.0.0.0:7077")
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
			MaxKeepaliveDuration: 2 * time.Second,
			ReadTimeout:          2 * time.Second,
		}
		if err := proxy.Serve(ln, 30*time.Second); err != nil {
			panic(err)
		}
	}()
	conn, err := net.Dial("tcp4", "0.0.0.0:7077")
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

	time.Sleep(100 * time.Millisecond)
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\n\r\n")
	result, err := bufio.NewReader(conn).ReadString('.')
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if result != "This is a proxy server" {
		t.Fatalf("an error occurred when send get request")
	}

	time.Sleep(2 * time.Second)
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\n\r\n")
	_, err = bufio.NewReader(conn).ReadString('\n')
	if err != io.EOF {
		t.Fatalf("unexpected error: %s, expected EOF", err)
	}
}

// test big header parse
func testBigHeader(t *testing.T) {
	Cache := ""
	for i := 0; i < 10000; i++ {
		Cache += "t"
	}
	Cache += "ewpZ8WDfBU095k+r/6v6GA=="
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

	req, err := nethttp.NewRequest("GET", "http://127.0.0.1:9990", nil)
	req.Header.Set("Sec-WebSocket-Key", Cache)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	_, err = c.Do(req)
	if !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("unexpected error: %s, expected error: EOF", err.Error())
	}
}

// test graceful shut down
func TestGracefulShutDown(t *testing.T) {
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
	go func() {
		ln, err := net.Listen("tcp4", "0.0.0.0:7078")
		if err != nil {
			return
		}
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		proxy.Serve(ln, 5*time.Second)
	}()
	time.Sleep(1 * time.Second)
	conn, err := net.Dial("tcp4", "0.0.0.0:7078")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	go func() {
		err = proxy.GracefulShutdown()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\n\r\n")
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if status != "HTTP/1.1 400 Bad Request\r\n" {
		t.Fatalf("an error occurred when send get request")
	}
	conn.Close()

	time.Sleep(3 * time.Second)
	conn, err = net.Dial("tcp4", "0.0.0.0:7078")
	if err == nil {
		t.Fatal("expected error: connection refused")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("unexpected error: %s", err)
	}
}

// test using proxy hijack and url send to different proxy
func testUsingProxyHijackAndURLSendToDifferProxy(t *testing.T) {
	superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 3128, superproxy.ProxyTypeHTTP, "", "", false, "")
	proxy := Proxy{
		BufioPool:   &bufiopool.Pool{},
		Client:      client.Client{},
		ProxyLogger: &log.DefaultLogger{},
		Handler: Handler{
			ShouldAllowConnection: func(conn net.Addr) bool {
				return true
			},
			ShouldDecryptHost: func(hostWithPort string) bool {
				return false
			},
			URLProxy: func(hostWithPort string, uri []byte) *superproxy.SuperProxy {
				if strings.Contains(hostWithPort, "127.0.0.1:9333") {
					return nil
				}
				if len(uri) == 0 {
					//this is a connections should not decrypt
					fmt.Println(hostWithPort)
				}
				return superProxy
			},
			HijackerPool: &CompleteHijackerPool{},
		},
	}
	go func() {
		ln, err := net.Listen("tcp4", "0.0.0.0:7555")
		if err != nil {
			return
		}
		if err := proxy.Serve(ln, 30*time.Second); err != nil {
			panic(err)
		}
	}()
	go func() {
		nethttp.HandleFunc("/sproxy", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			fmt.Fprintf(w, "Hello proxy!")
		})
		nethttp.ListenAndServe(":9333", nil)
	}()
	cproxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 7555))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy: cproxy,
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, err := nethttp.NewRequest("GET", "http://127.0.0.1:9333/sproxy", nil)
	req.Header.Set("Cache", "no-cache")
	req.Header.Set("Cookie", "NID=126=VEQk0MLRs1D2e5LMm8xkSyakyyr0_pEite-M8OAIh23FIzFCaoEAJkaeyIioj_ExnEKjdXUa4dMGdXVmS6bW3-E2xIZU89F3dcI87OUnH5RjN-xbtLlYdEy2OsAoPYQib4AiozI; 1P_JAR=2018-3-19-9")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if string(body) != "Hello proxy!" {
		t.Fatal("An error occurred: proxy can't send request")
	}

	req, err = nethttp.NewRequest("GET", "http://127.0.0.1:9990", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err = ioutil.ReadAll(resp.Body)
	if string(body) != "Hello world!" {
		t.Fatal("An error occurred: proxy can't send request")
	}

	if !bytes.Contains(bReq.Bytes(), []byte("Cache")) {
		t.Fatal("Hijack do not save request")
	}

	if !bytes.Contains(bReq.Bytes(), []byte("Host")) {
		t.Fatal("Hijack do not save request")
	}

	if !bytes.Contains(bReq.Bytes(), []byte("Cookie")) {
		t.Fatal("Hijack do not save request")
	}

	if !bytes.Contains(bReq.Bytes(), []byte("User-Agent")) {
		t.Fatal("Hijack do not save request")
	}

	if !bytes.Contains(bResp.Bytes(), []byte("Hello world")) {
		t.Fatal("Hijack don't save response")
	}

	if !bytes.Contains(bResp.Bytes(), []byte("Hello proxy")) {
		t.Fatal("Hijack don't save response")
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

var bReq = bytebufferpool.MakeFixedSizeByteBuffer(100)
var bResp = bytebufferpool.MakeFixedSizeByteBuffer(100)

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

type CompleteHijackerPool struct {
	pool sync.Pool
}

//Get get a simple hijacker from pool
func (p *CompleteHijackerPool) Get(clientAddr net.Addr,
	targetHost string, method, path []byte) hijack.Hijacker {
	v := p.pool.Get()
	var h *completeHijacker
	if v == nil {
		h = &completeHijacker{}
	} else {
		h = v.(*completeHijacker)
	}
	h.Set(clientAddr, targetHost, method, path)
	return h
}

//Put puts a simple hijacker back to pool
func (p *CompleteHijackerPool) Put(s hijack.Hijacker) {
	p.pool.Put(s)
}

type completeHijacker struct {
	clientAddr, targetHost string
	method, path           []byte
}

func (s *completeHijacker) Set(clientAddr net.Addr,
	host string, method, path []byte) {
	s.clientAddr = clientAddr.String()
	s.targetHost = host
	s.method = method
	s.path = path
}
func (s *completeHijacker) OnRequest(header http.Header, rawHeader []byte) io.Writer {
	bReq.Write(rawHeader)
	return bReq
}

func (s *completeHijacker) HijackResponse() io.Reader {
	return nil
}

func (s *completeHijacker) OnResponse(respLine http.ResponseLine,
	header http.Header, rawHeader []byte) io.Writer {
	return bResp
}
