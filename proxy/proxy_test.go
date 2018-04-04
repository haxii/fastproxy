package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/balinor2017/fastproxy/http"
	"github.com/balinor2017/fastproxy/superproxy"
	"github.com/balinor2017/log"
)

var (
	simpleProxyPort                                                                             = "5050"
	simpleServerPort                                                                            = ":9990"
	simpleHTTPSServerPort                                                                       = ":444"
	httpsProxyAddr                                                                              = "0.0.0.0:5060"
	httpsProxyPort                                                                              = ":5060"
	simpleServer, keepAliveServer, simpleProxy, httpsServer, httpProxy, httpsProxy, socks5Proxy func()
)

func testInit(t *testing.T) {
	simpleServer = func() {
		nethttp.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.Header().Set("Connection", "keep-alive")
			fmt.Fprintf(w, "Hello world%s!", r.URL.Path[1:])
		})
		nethttp.ListenAndServe(simpleServerPort, nil)
	}

	keepAliveServer = func() {
		ln, _ := net.Listen("tcp", ":9900")
		i := 0
		var keepConn net.Conn
		var closeConn net.Conn
		for {
			conn, _ := ln.Accept()
			b := make([]byte, 100)
			conn.Read(b)
			if i < 1 {
				keepConn = conn
			} else if i == 1 {
				closeConn = conn
			}
			if strings.Contains(string(b), "/keep-alive") {
				keepConn.Write([]byte("HTTP/1.1 200 ok\r\nConnection:keep-alive\r\n\r\n"))
			} else {
				if i == 1 {
					conn.Write([]byte("HTTP/1.1 200 ok\r\nConnection:close\r\n\r\n"))
				}
				closeConn.Close()
			}
			i++
		}
	}

	simpleProxy = func() {
		proxy := Proxy{
			ServerIdleDuration: 30 * time.Second,
			Logger:             &log.DefaultLogger{},
			Handler: Handler{
				ShouldAllowConnection: func(conn net.Addr) bool {
					return true
				},
				ShouldDecryptHost: func(userData *UserData, hostWithPort string) bool {
					return false
				},
				URLProxy: func(userData *UserData, hostWithPort string, uri []byte) *superproxy.SuperProxy {
					return nil
				},
				RewriteURL: func(userdata *UserData, hostWithPort string) string {
					return hostWithPort
				},
			},
		}
		if err := proxy.Serve("tcp4", "0.0.0.0:"+simpleProxyPort); err != nil {
			panic(err)
		}
	}

	httpsServer = func() {
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
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		f.Write([]byte(serverKey))
		f.Close()
		err = nethttp.ListenAndServeTLS(simpleHTTPSServerPort, ".server.crt", ".server.key", nil)
		if err != nil {
			slog.Fatal("ListenAndServe: ", err)
		}
	}
	/*
	   	httpsProxy = func() {
	   		serverCrt := `
	   -----BEGIN CERTIFICATE-----
	   MIIB1jCCATigAwIBAgIBATAKBggqhkjOPQQDBDAdMRswGQYDVQQDExJHZW9UcnVz
	   dCBHbG9iYWwgQ0EwHhcNMTcwOTAyMTUyNzE0WhcNMjIwOTAxMTUyNzE0WjAdMRsw
	   GQYDVQQDExJHZW9UcnVzdCBHbG9iYWwgQ0EwgZswEAYHKoZIzj0CAQYFK4EEACMD
	   gYYABAGVr9JHBx3sGRZ62wb4vjsjgf0e9AQqhNxO7m7uASsHPoiXsfdV0GD/gXKf
	   rsNgtvm8FBQMAtuVsgTgfqJPji2jwgC7xTpZB8BFflW4t6G86ifD87fXLNzcuFgo
	   v5N8pomYMSyraVEWvZZ6Hl2VjL32ZkH/iDQpZKacJLwaaYpYMX39UKMmMCQwDgYD
	   VR0PAQH/BAQDAgH+MBIGA1UdEwEB/wQIMAYBAf8CAQIwCgYIKoZIzj0EAwQDgYsA
	   MIGHAkIA1ib8nXsLetEfjXvDY71nBGF6my6Nk+aMp/vNi5MbYIaz+TPWKHUq4+zo
	   49pxtUwEwWKKMpU2GYvJUgaz35SzD0oCQVrs1niHmySDjCnrUHJOawo+s2zL6svd
	   FJ6RtJFfkqJ7nh/8/djL0gBbmcCzPnma0ermJxHABxWnIVYPCYuN8GJR
	   -----END CERTIFICATE-----
	   `
	   		superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 3129, superproxy.ProxyTypeHTTPS, "", "", serverCrt)
	   		proxy := Proxy{
	   			ServerIdleDuration: 30 * time.Second,
	   			Logger:             &log.DefaultLogger{},
	   			Handler: Handler{
	   				ShouldAllowConnection: func(conn net.Addr) bool {
	   					return true
	   				},
	   				ShouldDecryptHost: func(userData *UserData, hostWithPort string) bool {
	   					return false
	   				},
	   				URLProxy: func(userData *UserData, hostWithPort string, uri []byte) *superproxy.SuperProxy {
	   					return superProxy
	   				},
	   				RewriteURL: func(userdata *UserData, hostWithPort string) string {
	   					return hostWithPort
	   				},
	   			},
	   		}
	   		if err := proxy.Serve("tcp4", httpsProxyPort); err != nil {
	   			panic(err)
	   		}
	   	}
	*/
	socks5Proxy = func() {
		superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 9099, superproxy.ProxyTypeSOCKS5, "", "", "")
		proxy := Proxy{
			ServerIdleDuration: 30 * time.Second,
			Logger:             &log.DefaultLogger{},
			Handler: Handler{
				ShouldAllowConnection: func(conn net.Addr) bool {
					return true
				},
				ShouldDecryptHost: func(userData *UserData, hostWithPort string) bool {
					return false
				},
				URLProxy: func(userData *UserData, hostWithPort string, uri []byte) *superproxy.SuperProxy {
					return superProxy
				},
				RewriteURL: func(userdata *UserData, hostWithPort string) string {
					return hostWithPort
				},
			},
		}
		if err := proxy.Serve("tcp4", "0.0.0.0:5030"); err != nil {
			panic(err)
		}
	}

	httpProxy = func() {
		superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 3128, superproxy.ProxyTypeHTTP, "", "", "")
		proxy := Proxy{
			ServerIdleDuration: 30 * time.Second,
			Logger:             &log.DefaultLogger{},
			Handler: Handler{
				ShouldAllowConnection: func(conn net.Addr) bool {
					return true
				},
				ShouldDecryptHost: func(userData *UserData, hostWithPort string) bool {
					return false
				},
				URLProxy: func(userData *UserData, hostWithPort string, uri []byte) *superproxy.SuperProxy {
					return superProxy
				},
				RewriteURL: func(userdata *UserData, hostWithPort string) string {
					return hostWithPort
				},
			},
		}
		if err := proxy.Serve("tcp4", "0.0.0.0:5040"); err != nil {
			panic(err)
		}
	}

	go simpleServer()
	go httpsServer()
	go keepAliveServer()
	time.Sleep(time.Second)
	defer os.Remove(".server.key")
	defer os.Remove(".server.crt")
}

func TestCommon(t *testing.T) {
	testInit(t)
	httpReq, _ := nethttp.NewRequest("GET", "http://127.0.0.1:9990", nil)
	httpsReq, _ := nethttp.NewRequest("GET", "https://127.0.0.1:444", nil)
	Cache := ""
	for i := 0; i < 10000; i++ {
		Cache += "t"
	}
	testProxyServe(t, simpleProxy, "GET / HTTP/1.1\r\n\r\n", "HTTP/1.1 400 Bad Request\r\n")
	testHTTPRequest(t, httpReq, "http://127.0.0.1:5050", "Hello world!", false)
	testHTTPRequest(t, httpsReq, "http://127.0.0.1:5050", "Hello world!", true)

	testHTTPSuperProxy(t, "http://127.0.0.1:5040", httpReq, httpsReq, "Hello world!", httpProxy)
	//testHTTPSSuperProxy(t, "http://127.0.0.1:5060", httpReq, httpsReq, "Hello world!", httpsProxy)
	testSocks5SuperProxy(t, "http://127.0.0.1:5030", httpReq, httpsReq, "Hello world!", socks5Proxy)

	testBigHeader(t, "http://127.0.0.1:5050", httpReq, Cache, "EOF")

	testGracefulShutDown(t)
	testUsingProxyHijackAndURLSendToDifferProxy(t)
	testHostsRewrite(t)

	testProxyKeepConnectionAndClose(t)
}

func testProxyServe(t *testing.T, simpleFunc func(), reqString, expResult string) {
	go simpleFunc()
	simpleServerAddr := "0.0.0.0:" + simpleProxyPort
	conn, err := net.Dial("tcp4", simpleServerAddr)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	fmt.Fprintf(conn, reqString)
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if status != expResult {
		t.Fatalf("an error occurred when send get request")
	}
}

//test send http request with fastproxy
func testHTTPRequest(t *testing.T, req *nethttp.Request, proxyAddr, expString string, isSSL bool) {
	simpleProxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	var transport *nethttp.Transport
	if !isSSL {
		transport = &nethttp.Transport{
			Proxy: simpleProxy,
		}
	} else {
		transport = &nethttp.Transport{
			Proxy: simpleProxy,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "localhost"},
		}
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if string(body) != expString {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

// test send http request with http superproxy
func testHTTPSuperProxy(t *testing.T, proxyAddr string, httpReq, httpsReq *nethttp.Request, expResult string, proxy func()) {
	go proxy()
	time.Sleep(time.Second)
	proxyWithHTTPSuperProxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy: proxyWithHTTPSuperProxy,
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	resp, err := c.Do(httpReq)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if string(body) != expResult {
		t.Fatal("An error occurred: proxy can't send request")
	}

	transport = &nethttp.Transport{
		Proxy: proxyWithHTTPSuperProxy,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
		},
	}
	c = nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	resp, err = c.Do(httpsReq)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err = ioutil.ReadAll(resp.Body)
	if string(body) != expResult {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

// test send http request with https superproxy
func testHTTPSSuperProxy(t *testing.T, proxyAddr string, httpReq, httpsReq *nethttp.Request, expResult string, proxy func()) {
	go proxy()
	proxyWithHTTPSSuperProxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err
	}
	caCert, err := ioutil.ReadFile(".server.crt")
	if err != nil {
		t.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	c := &nethttp.Client{
		Transport: &nethttp.Transport{
			Proxy: proxyWithHTTPSSuperProxy,
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
			},
		},
	}
	resp, err := c.Do(httpReq)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if string(body) != expResult {
		t.Fatal("An error occurred: proxy can't send request")
	}
	resp, err = c.Do(httpsReq)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err = ioutil.ReadAll(resp.Body)
	if string(body) != expResult {
		t.Fatal("An error occurred: proxy can't send request")
	}
}

// test send http request with socks5 superproxy
func testSocks5SuperProxy(t *testing.T, proxyAddr string, httpReq, httpsReq *nethttp.Request, expResult string, proxy func()) {
	go proxy()
	proxyWithSocks5SuperProxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy: proxyWithSocks5SuperProxy,
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	resp, err := c.Do(httpReq)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if string(body) != "Hello world!" {
		t.Fatal("An error occurred: proxy can't send request")
	}

	transport = &nethttp.Transport{
		Proxy: proxyWithSocks5SuperProxy,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true,
			ServerName: "localhost"},
	}
	c = nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	resp, err = c.Do(httpsReq)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err = ioutil.ReadAll(resp.Body)
	if string(body) != expResult {
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

// test big header parse
func testBigHeader(t *testing.T, proxyAddr string, req *nethttp.Request, bigCache string, expErr string) {
	Cache := bigCache + "ewpZ8WDfBU095k+r/6v6GA=="
	simpleProxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err
	}
	transport := &nethttp.Transport{
		Proxy: simpleProxy,
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	req.Header.Set("Sec-WebSocket-Key", Cache)
	_, err := c.Do(req)
	if !strings.Contains(err.Error(), expErr) {
		t.Fatalf("unexpected error: %s, expected error: EOF", err.Error())
	}
}

func testProxyKeepConnectionAndClose(t *testing.T) {
	simpleProxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse("http://127.0.0.1:5050")
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err
	}
	transport := &nethttp.Transport{
		Proxy: simpleProxy,
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	req, _ := nethttp.NewRequest("GET", "http://127.0.0.1:9900/keep-alive", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error:%s", err)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	if string(body) != "" {
		t.Fatal("An error occurred: proxy can't send request")
	}
	req, _ = nethttp.NewRequest("GET", "http://127.0.0.1:9900/", nil)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error:%s", err)
	}

	req, _ = nethttp.NewRequest("GET", "http://127.0.0.1:9900/", nil)
	resp, err = c.Do(req)
	if err == nil {
		t.Fatal("unexpected error: request canceled")
	}
	if !strings.Contains(err.Error(), "request canceled") {
		t.Fatalf("unexpected error: %s", err)
	}
}

// test graceful shut down
func testGracefulShutDown(t *testing.T) {
	proxy := Proxy{
		ServerShutdownWaitTime: 10 * time.Second,
		Logger:                 &log.DefaultLogger{},
		Handler: Handler{
			ShouldAllowConnection: func(conn net.Addr) bool {
				return true
			},
			ShouldDecryptHost: func(userData *UserData, hostWithPort string) bool {
				return true
			},
			URLProxy: func(userData *UserData, hostWithPort string, uri []byte) *superproxy.SuperProxy {
				return nil
			},
			RewriteURL: func(userdata *UserData, hostWithPort string) string {
				return hostWithPort
			},
		},
	}
	go func() {
		proxy.Serve("tcp4", "0.0.0.0:7078")
	}()
	time.Sleep(1 * time.Second)
	conn, err := net.Dial("tcp4", "0.0.0.0:7078")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	time.Sleep(1 * time.Second)
	go func() {
		err = proxy.ShutDown()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}()
	time.Sleep(1 * time.Second)
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\n\r\n")
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if status != "HTTP/1.1 400 Bad Request\r\n" {
		t.Fatalf("an error occurred when send get request")
	}
	conn.Close()

	time.Sleep(10 * time.Second)
	conn, err = net.Dial("tcp4", "0.0.0.0:7078")
	if err == nil {
		t.Fatal("expected error: connection refused")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		if !strings.Contains(err.Error(), "connection reset by peer") {
			t.Fatalf("unexpected error: %s", err)
		}
	}
}

// test using proxy hijack and url send to different proxy
func testUsingProxyHijackAndURLSendToDifferProxy(t *testing.T) {
	superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 3128, superproxy.ProxyTypeHTTP, "", "", "")
	dataForSigning := ""
	proxy := Proxy{
		Logger: &log.DefaultLogger{},
		Handler: Handler{
			ShouldAllowConnection: func(conn net.Addr) bool {
				return true
			},
			ShouldDecryptHost: func(userdata *UserData, hostWithPort string) bool {
				return false
			},
			URLProxy: func(userdata *UserData, hostWithPort string, uri []byte) *superproxy.SuperProxy {
				if strings.Contains(hostWithPort, "127.0.0.1:9333") {
					dataForSigning = "No super proxy can use for fast proxy"
					return nil
				}
				return superProxy
			},
			RewriteURL: func(userdata *UserData, hostWithPort string) string {
				return hostWithPort
			},
		},
	}
	go func() {
		if err := proxy.Serve("tcp4", "0.0.0.0:7555"); err != nil {
			panic(err)
		}
	}()
	go func() {
		nethttp.HandleFunc("/sproxy", func(w nethttp.ResponseWriter, r *nethttp.Request) {
			fmt.Fprintf(w, "Hello proxy!")
		})
		nethttp.ListenAndServe(":9333", nil)
	}()
	newProxyWithSuperProxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 7555))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err

	}
	transport := &nethttp.Transport{
		Proxy: newProxyWithSuperProxy,
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

	if !strings.Contains(dataForSigning, "No super proxy can use for fast proxy") {
		t.Fatal("Proxy send request using super proxy, expected should not use super proxy")
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

	if !bytes.Contains(bReq.Bytes(), []byte("Host")) {
		t.Fatal("Hijack do not save request")
	}
}

func testHostsRewrite(t *testing.T) {
	proxy := Proxy{
		Logger: &log.DefaultLogger{},
		Handler: Handler{
			ShouldAllowConnection: func(conn net.Addr) bool {
				return true
			},
			ShouldDecryptHost: func(userdata *UserData, hostWithPort string) bool {
				return false
			},
			URLProxy: func(userdata *UserData, hostWithPort string, uri []byte) *superproxy.SuperProxy {
				return nil
			},
			RewriteURL: func(userdata *UserData, hostWithPort string) string {
				if hostWithPort == "127.0.0.1:9990" {
					return "127.0.0.1:5050"
				}
				return hostWithPort
			},
		},
	}
	go func() {
		if err := proxy.Serve("tcp4", "0.0.0.0:7666"); err != nil {
			panic(err)
		}
	}()

	newProxy := func(r *nethttp.Request) (*url.URL, error) {
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", "127.0.0.1", 7666))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		return proxyURL, err
	}
	transport := &nethttp.Transport{
		Proxy: newProxy,
	}
	c := nethttp.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	req, err := nethttp.NewRequest("GET", "http://127.0.0.1:9333/sproxy", nil)
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

	req, err = nethttp.NewRequest("GET", "http://127.0.0.1:9990/", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	resp, err = c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	body, err = ioutil.ReadAll(resp.Body)
	if string(body) == "hello world!" {
		t.Fatal("An error occurred: proxy can't rewrite url")
	}

	if !strings.Contains(string(body), "This is a proxy server") {
		t.Fatal("An error occurred: proxy can't rewrite url")
	}

}

//SimpleHijackerPool implements the HijackerPool based on simpleHijacker & sync.Pool
type SimpleHijackerPool struct {
	pool sync.Pool
}

//Get get a simple hijacker from pool
func (p *SimpleHijackerPool) Get(clientAddr net.Addr,
	targetHost string, method, path []byte) Hijacker {
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
func (p *SimpleHijackerPool) Put(s Hijacker) {
	p.pool.Put(s)
}

type CompleteHijackerPool struct {
	pool sync.Pool
}

//Get get a simple hijacker from pool
func (p *CompleteHijackerPool) Get(clientAddr net.Addr,
	targetHost string, method, path []byte) Hijacker {
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
func (p *CompleteHijackerPool) Put(s Hijacker) {
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
