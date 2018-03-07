package http

import (
	"bufio"
	"io"
	"strings"
	"testing"

	"github.com/haxii/fastproxy/bytebufferpool"
)

func TestParseHeaderFields(t *testing.T) {
	var err error
	header := &Header{}
	header.Reset()
	s := `GET / HTTP/1.1
	Content-Length: 72
	Content-Type: multipart/form-data
	`
	br := bufio.NewReader(strings.NewReader(s))
	bf := bytebufferpool.Get()
	err = header.ParseHeaderFields(br, bf)
	if err != nil {
		if err != io.EOF {
			t.Fatalf("unexpected error: %s", err.Error())
		}
	}
}
