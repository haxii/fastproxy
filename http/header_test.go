package http

import (
	"bufio"
	"io"
	"strings"
	"testing"

	"github.com/haxii/fastproxy/bytebufferpool"
)

func TestParseHeaderFields(t *testing.T) {
	testParseHeader(t, "GET / HTTP/1.1\r\n\r\n", nil, "", false, false)
	testParseHeader(t, "GET / HTTP/1.1\n\n", nil, "", false, false)
	testParseHeader(t, "GET / HTTP/1.1\r\n", io.EOF, "", false, false)
	testParseHeader(t, "GET / HTTP/1.1\r\nConnection: close\r\n\r\n", nil, "", true, false)
	testParseHeader(t, "GET / HTTP/1.1\r\nProxy-Connection: close\r\n\r\n", nil, "", false, true)
	testParseHeader(t, "GET / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n", nil, "text/plain", false, false)
}

func testParseHeader(t *testing.T, s string, expErr error, expContentType string, expConnBoolen bool, expProxyConnBoolen bool) {
	var err error
	header := &Header{}
	header.Reset()
	br := bufio.NewReader(strings.NewReader(s))
	bf := bytebufferpool.Get()
	_, err = header.ParseHeaderFields(br, bf)
	if err != expErr {
		t.Fatalf("unexpected error: %s", err)
	}
	if header.IsConnectionClose() != expConnBoolen {
		t.Fatalf("Connection status is error")
	}
	if header.IsProxyConnectionClose() != expProxyConnBoolen {
		t.Fatalf("Proxy Connection status is error")
	}
	if header.ContentType() != expContentType {
		t.Fatalf("Content type is error")
	}
}
