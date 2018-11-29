package superproxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
)

// TestNewSuperProxy test new super proxy with http, https and socks5 types
// and test if those superproxy can make tunnel with a simple server
func TestNewSuperProxy(t *testing.T) {
	var j = 0
	go func() {
		http.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
			j++
			if j > 2 {
				time.Sleep(2 * time.Second)
				conn, _, _ := w.(http.Hijacker).Hijack()
				j--
				conn.Close()
			}
			if j < 3 {
				time.Sleep(3 * time.Second)
				w.WriteHeader(200)
				j--
			}
		})
		http.ListenAndServe(":9999", nil)
	}()
	time.Sleep(time.Millisecond * 10)
	testNewSuperProxyWithHTTPSProxy(t)
	testNewSuperProxyWithHTTPType(t)
	testNewSuperProxyWithSocks5Type(t)
	testSuperProxyConcurrency(t)
}

// test new super proxy with http type
func testNewSuperProxyWithHTTPType(t *testing.T) {
	superProxy, err := NewSuperProxy("localhost", uint16(3128), ProxyTypeHTTP, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if superProxy.GetProxyType() != ProxyTypeHTTP {
		t.Fatalf("unexpected proxy type")
	}
	if superProxy.HostWithPort() != "localhost:3128" {
		t.Fatalf("unexpected host with port")
	}
	if !bytes.Equal(superProxy.HostWithPortBytes(), []byte("localhost:3128")) {
		t.Fatalf("unexpected host with port bytes")
	}
	pool := bufiopool.New(1, 1)
	conn, err := superProxy.MakeTunnel(pool, "localhost:9999")
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if _, err = conn.Write([]byte("GET /test HTTP/1.1\r\nHost: localhost:9999\r\n\r\n")); err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	result := make([]byte, 1000)
	if _, err = conn.Read(result); err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(result), "HTTP/1.1 200 OK") {
		t.Fatalf("unexpected result")
	}
}

// test new super proxy with socks5 type
func testNewSuperProxyWithSocks5Type(t *testing.T) {
	superProxy, err := NewSuperProxy("localhost", uint16(9099), ProxyTypeSOCKS5, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if superProxy.GetProxyType() != ProxyTypeSOCKS5 {
		t.Fatalf("unexpected proxy type")
	}
	if superProxy.HostWithPort() != "localhost:9099" {
		t.Fatalf("unexpected host with port")
	}
	if !bytes.Equal(superProxy.HostWithPortBytes(), []byte("localhost:9099")) {
		t.Fatalf("unexpected host with port bytes")
	}

	pool := bufiopool.New(1, 1)
	conn, err := superProxy.MakeTunnel(pool, "localhost:9999")
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if _, err = conn.Write([]byte("GET /test HTTP/1.1\r\nHost: localhost:9999\r\n\r\n")); err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	result := make([]byte, 1000)
	if _, err = conn.Read(result); err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(result), "HTTP/1.1 200 OK") {
		t.Fatalf("unexpected result")
	}
	defer conn.Close()
}

// test new super proxy with https type
func testNewSuperProxyWithHTTPSProxy(t *testing.T) {
	serverCrt := `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQCGekFEop87ETANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJD
TjAeFw0xODA0MjgwOTUwMzdaFw0yODA0MjUwOTUwMzdaMA0xCzAJBgNVBAYTAkNO
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzq8bjYMevwPn2KbFJYV9
msdhuyp1wa9YStDJJE+sYoZb7KKAgh+2wDO0MX4cnyEnVAnmWYYdBjoZJc51XCNG
yEei1bwR1EFNcTXa4tOclymOn5jgT1jNCG+eNXATUPZczaF/n4R3CEJslolhdYjd
cpRBxFh04sOf3kX6zro5YJij8kKBCK87MyItFLL+ErLx5n0wFwkLY3MaxYn8qfhY
Q5UPxVFVKWtppEscYeBH0C5cxUZ8hwySCGYbnU7IcqVCzEmw+hOxXd3eTjej+EoV
HOOtHrutxkCkIndlEnXKOFCkhCZoNw9V7dI8advS58pv/2UZZfh3etUNYJBKcZ4M
iQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAX7XDkPDSaya3C3wSh9MX/PHG5wErR
bJ1ab2+erphS6NzSf7sWY3BlN7hDwbpEJf2Iepw2psKqKUasLpuDSb0KkLTusq4N
qsXU+/XDtndgrPorYsH3tA6U6cMjzLrPEbBAP26AI7yXj9RX5Ua3Cc70Uzj94YQO
Zm4M5BkKXUiY7YdCpgdcAP8qOdqRX+EoRJ/UeuifBeQKCusiY66wYosychvsqE+K
h0cEia4cq5miAgYT3lkfyFJsLFcvZ2Jj/c/eulT155LNqqjaKT06IhvnaLrdgpVX
/HcVZierphDDxIxYkBXGAGgEUHvT2PSbFxFnwxJg67cXVKBNIMgFgTCI
-----END CERTIFICATE-----
`
	f, err := os.Create(".server.crt")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	f.Write([]byte(serverCrt))
	f.Close()

	defer os.Remove(".server.crt")

	superProxy, err := NewSuperProxy("localhost", uint16(3129), ProxyTypeHTTPS, "", "", ".server.crt")
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if superProxy.GetProxyType() != ProxyTypeHTTPS {
		t.Fatalf("unexpected proxy type")
	}
	if superProxy.HostWithPort() != "localhost:3129" {
		t.Fatalf("unexpected host with port")
	}
	if !bytes.Equal(superProxy.HostWithPortBytes(), []byte("localhost:3129")) {
		t.Fatalf("unexpected host with port bytes")
	}
	superProxy.tlsConfig.InsecureSkipVerify = true
	pool := bufiopool.New(1, 1)
	conn, err := superProxy.MakeTunnel(pool, "localhost:9999")
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if _, err = conn.Write([]byte("GET /test HTTP/1.1\r\nHost: localhost:9999\r\n\r\n")); err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	result := make([]byte, 1000)
	if _, err = conn.Read(result); err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(result), "HTTP/1.1 200 OK") {
		t.Fatalf("unexpected result")
	}
}

// test new super proxy with error parameters
func TestErrorParameters(t *testing.T) {
	_, err := NewSuperProxy("", uint16(3129), ProxyTypeHTTPS, "", "", ".server.crt")
	if err == nil {
		t.Fatalf("expected error: nil host provided")
	}
	if !strings.Contains(err.Error(), "nil host provided") {
		t.Fatalf("expected error: nil host proivded, but get an unexpected error: %s", err)
	}

	_, err = NewSuperProxy("localhost", uint16(0), ProxyTypeHTTPS, "", "", ".server.crt")
	if err == nil {
		t.Fatalf("expected error: nil port provided")
	}
	if !strings.Contains(err.Error(), "nil port provided") {
		t.Fatalf("expected error: nil port provided, but get an unexpected error: %s", err)
	}
}

// test if super proxy can limit concurrency
func testSuperProxyConcurrency(t *testing.T) {
	for i := 0; i < 4; i++ {
		go func() {
			conn, err := net.Dial("tcp4", "localhost:9999")
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if _, err = conn.Write([]byte("GET /test HTTP/1.1\r\nHost: localhost:9999\r\n\r\n")); err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			result := make([]byte, 1000)
			if i < 2 {
				if _, err = conn.Read(result); err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
				if !strings.Contains(string(result), "HTTP/1.1 200 OK") {
					t.Fatalf("unexpected result")
				}
			}
			if i > 1 {
				if _, err = conn.Read(result); err == nil {
					t.Fatal("expected error: EOF")
				}
				if err != io.EOF {
					t.Fatalf("expected error: EOF, but get unexpected error: %s", err)
				}
			}
			conn.Close()
		}()
		time.Sleep(1 * time.Second)
	}
	time.Sleep(time.Second)
	superProxy, err := NewSuperProxy("localhost", uint16(3128), ProxyTypeHTTP, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	pool := bufiopool.New(1, 1)
	superProxy.SetMaxConcurrency(2)
	time.Sleep(5 * time.Second)
	for i := 0; i < 6; i++ {
		superProxy.AcquireToken()
		go func() {
			conn, err := superProxy.MakeTunnel(pool, "localhost:9999")
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			if _, err = conn.Write([]byte("GET /test HTTP/1.1\r\nHost: localhost:9999\r\n\r\n")); err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			result := make([]byte, 1000)
			if _, err = conn.Read(result); err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			if !strings.Contains(string(result), "HTTP/1.1 200 OK") {
				t.Fatalf("unexpected result: %s", result)
			}
			superProxy.PushBackToken()
		}()
		time.Sleep(1 * time.Second)
	}
}
