package transport

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/haxii/fastproxy/cert"
)

func TestTransportForwordAndDial(t *testing.T) {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			fmt.Fprint(w, "GET /hello HTTP/1.1\r\nHOST: 127.0.0.1:9999\r\n\r\n")
		})
		http.ListenAndServe(":9990", nil)
	}()
	go func() {
		http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
			fmt.Fprint(w, "Hello World")
		})
		http.ListenAndServe(":9999", nil)
	}()
	connDst, err := Dial("127.0.0.1:9999")
	if err != nil {
		t.Fatal("dial dst error")
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://localhost:9990", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	_, err = Forward(connDst, resp.Body)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	result := make([]byte, 1000)
	_, err = connDst.Read(result)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(result), "Hello World") {
		t.Fatal("transport error")
	}
	defer connDst.Close()
}

func TestTransportDialTLS(t *testing.T) {
	cfg := cert.MakeClientTLSConfig("127.0.0.1", "server")
	conn, err := DialTLS("127.0.0.1:443", cfg)
	if err != nil {
		t.Fatalf("Dial error: %s", err.Error())
	}
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	result := make([]byte, 1000)
	_, err = conn.Read(result)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(result), "HTTP/1.1 500") {
		t.Fatal("DialTLS doesn't work")
	}
}
