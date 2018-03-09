package http

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/fastfork/fastproxy/bytebufferpool"
)

func TestHttpRequest(t *testing.T) {
	s := "GET / HTTP/1.1\r\n" +
		"Host: localhost:10000\r\n" +
		"\r\n"
	req := &Request{}
	br := bufio.NewReader(strings.NewReader(s))
	err := req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !bytes.Equal(req.Method(), []byte("GET")) {
		t.Fatalf("Read from bufio reader is error")
	}
	if req.GetReqLineSize() != 16 {
		t.Fatalf("Read from bufio reader size is error")
	}
	if !bytes.Equal(req.Protocol(), []byte("HTTP/1.1")) {
		t.Fatalf("Protocol parse error")
	}
	req.Reset()
	if bytes.Equal(req.Method(), []byte("GET")) {
		t.Fatalf("Reset error")
	}
}

func TestHttpResponse(t *testing.T) {
	//s := "HTTP/1.1 200 ok\r\n" + "\r\n"
	resp := &Response{}
	//br := bufio.NewReader(strings.NewReader(s))
	byteBuffer := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bw := bufio.NewWriter(byteBuffer)
	err := resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	/*err = resp.ReadFrom(false, br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	err = resp.WriteTo(bw)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}*/
}
