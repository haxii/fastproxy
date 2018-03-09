package superproxy

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/haxii/fastproxy/bufiopool"
)

func TestNewSuperProxyWithHTTPType(t *testing.T) {
	superProxy, err := NewSuperProxy("ladder.haxii.com", uint16(1080), ProxyTypeHTTP, "", "", false)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if superProxy.GetProxyType() != ProxyTypeHTTP {
		t.Fatalf("unexpected proxy type")
	}
	if superProxy.HostWithPort() != "ladder.haxii.com:1080" {
		t.Fatalf("unexpected host with port")
	}
	if !bytes.Equal(superProxy.HostWithPortBytes(), []byte("ladder.haxii.com:1080")) {
		t.Fatalf("unexpected host with port bytes")
	}

	pool := bufiopool.New(1, 1)
	conn, err := superProxy.MakeTunnel(pool, "icanhazip.com:80")
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if _, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: icanhazip.com\r\n\r\n")); err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	result := make([]byte, 50)
	if _, err = conn.Read(result); err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(result), "HTTP/1.1 200 OK") {
		t.Fatalf("unexpected result")
	}
	defer conn.Close()
}

func TestNewSuperProxyWithSocksType(t *testing.T) {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
		})
		http.ListenAndServe(":9999", nil)
	}()
	superProxy, err := NewSuperProxy("localhost", uint16(9099), ProxyTypeSOCKS5, "", "", false)
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
	if _, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost:9999\r\n\r\n")); err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	result := make([]byte, 1000)
	if _, err = conn.Read(result); err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(result), "HTTP/1.1 201 Created") {
		t.Fatalf("unexpected result")
	}
	defer conn.Close()
}
