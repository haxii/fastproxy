package transport

import (
	"strings"
	"testing"

	"github.com/balinor2017/fastproxy/cert"
)

/*
func TestTransportForwordAndDial(t *testing.T) {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			fmt.Fprint(w, "GET /hello HTTP/1.1\r\nHOST: 127.0.0.1:9997\r\n\r\n")
		})
		http.ListenAndServe(":9990", nil)
	}()
	go func() {
		http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
			fmt.Fprint(w, "Hello World")
		})
		http.ListenAndServe(":9997", nil)
	}()
	connDst, err := Dial("127.0.0.1:9997")
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
	_, err = Forward(connDst, resp.Body, 1*time.Second)
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
*/
func TestTransportDialTLS(t *testing.T) {
	cfg := cert.MakeClientTLSConfig("", "")
	conn, err := DialTLS("127.0.0.1:3129", cfg)
	if err != nil {
		t.Fatalf("Dial error: %s", err.Error())
	}
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1:3129\r\n\r\n"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	result := make([]byte, 1000)
	_, err = conn.Read(result)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(result), "HTTP/1.1 400") {
		t.Fatalf("expected result is %s, but get unexpected result: %s", "HTTP/1.1 400", string(result))
	}
}
