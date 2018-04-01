package util

import (
	"bufio"
	"strings"
	"testing"

	"github.com/haxii/fastproxy/bytebufferpool"
)

func TestHex(t *testing.T) {
	buffer := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer)
	s := "A\r\n1234567890\r\n"
	br := bufio.NewReader(strings.NewReader(s))
	_, err := ReadHexInt(br, buffer)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	buffer.Reset()
	s = "10\r\n12345\r\n"
	br = bufio.NewReader(strings.NewReader(s))
	n, err := ReadHexInt(br, buffer)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if n != 16 {
		t.Fatalf("expected read numble is 16, but get %d", n)
	}

	buffer.Reset()
	s = "ysf\r\n123\r\n"
	br = bufio.NewReader(strings.NewReader(s))
	n, err = ReadHexInt(br, buffer)
	if err == nil {
		t.Fatal("expected error: empty hex number")
	}
	if err != errEmptyHexNum {
		t.Fatalf("expected error: empty hex number, but get unexpected error: %s", err)
	}

	buffer.Reset()
	s = "111111111111111111\r\n"
	br = bufio.NewReader(strings.NewReader(s))
	n, err = ReadHexInt(br, buffer)
	if err == nil {
		t.Fatal("expected error: too large hex number")
	}
	if err != errTooLargeHexNum {
		t.Fatalf("expected error: empty hex number, but get unexpected error: %s", err)
	}
}
