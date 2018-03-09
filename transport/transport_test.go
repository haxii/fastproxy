package transport

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
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
