package http

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseBodyField(t *testing.T) {
	testParseBodyFieldByBodyType(t, BodyTypeChunked, "5\r\nasdfg\r\n0\r\n\r\n")
	testParseBodyFieldByBodyType(t, BodyTypeFixedSize, "sdfzdfsdfewrfsdf\r\n\r\n")
	testParseBodyFieldByBodyType(t, BodyTypeIdentity, "sdfzdfsdfewrfsdf\r\n\r\n")
}

func testParseBodyFieldByBodyType(t *testing.T, bt BodyType, s string) {
	body := &Body{}
	br := bufio.NewReader(strings.NewReader(s))
	w := func(isChunkHeader bool, data []byte) (int, error) {
		return 0, nil
	}
	if _, err := body.Parse(br, bt, int64(len(s)), w); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}
