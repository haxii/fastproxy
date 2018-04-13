package util

import (
	"bufio"
	"strings"
	"testing"

	"github.com/balinor2017/fastproxy/bytebufferpool"
)

func testHex(t *testing.T, testString string, expErr error, expInt int) {
	buffer := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer)
	br := bufio.NewReader(strings.NewReader(testString))
	n, err := ReadHexInt(br, buffer)
	if err != expErr {
		t.Fatalf("expected error: %s, but get unexpected error: %s", expErr, err)
	}
	if n != expInt {
		t.Fatalf("expected result: %d, but get unexpected result: %d", expInt, n)
	}
}

func TestHex(t *testing.T) {
	testHex(t, "A\r\n1234567890\r\n", nil, 10)
	testHex(t, "10\r\n12345\r\n", nil, 16)
	testHex(t, "ysf\r\n123\r\n", errEmptyHexNum, -1)
	testHex(t, "111111111111111111\r\n", errTooLargeHexNum, -1)
}
