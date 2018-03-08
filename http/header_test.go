package http

import (
	"bufio"
	"strings"
	"testing"

	"github.com/haxii/fastproxy/bytebufferpool"
)

func TestParseHeaderFields(t *testing.T) {
	var err error
	header := &Header{}
	header.Reset()
	s := "GET / HTTP/1.0\r\nHost: foobar\r\nConnection: keep-alive\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(s))
	bf := bytebufferpool.Get()
	err = header.ParseHeaderFields(br, bf)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
}
