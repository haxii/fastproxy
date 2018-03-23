package http

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestParseBodyField(t *testing.T) {
	w := func(isChunkHeader bool, data []byte) (int, error) {
		return 0, nil
	}
	testParseBodyFieldByBodyType(t, BodyTypeChunked, "5\r\nasdfg\r\n0\r\n\r\n")
	testParseBodyFieldByBodyType(t, BodyTypeFixedSize, "sdfzdfsdfewrfsdf\r\n\r\n")
	testParseBodyFieldByBodyType(t, BodyTypeIdentity, "sdfzdfsdfewrfsdf\r\n\r\n")

	testParseBodyFieldWithErrorBody(t, BodyTypeChunked, "5\nasdfg\r\n0\r\n\r\n", `unexpected char '\n' at the end of chunk size`, w)
	testParseBodyFieldWithErrorBody(t, BodyTypeChunked, "5\rasdfg\r\n0\r\n\r\n", `unexpected char 'a' at the end of chunk size`, w)
	testParseBodyFieldWithErrorBody(t, BodyTypeChunked, "5\r\nsasfg\r\n0\n\r\n", `unexpected char '\n' at the end of chunk size`, w)
	testParseBodyFieldWithErrorBody(t, BodyTypeChunked, "5\r\nasdfg\r\n0\r\r\n", `unexpected char '\r' at the end of chunk size`, w)
	testParseBodyFieldWithErrorBody(t, BodyTypeChunked, "\r\nsasfg\r\n0\n\r\n", `empty hex number`, w)
	testParseBodyFieldWithErrorBody(t, BodyTypeChunked, "5\r\nasdfg\r\n\r\n\r\n", `empty hex number`, w)
	testParseBodyFieldWithErrorBody(t, BodyTypeChunked, "5\r\n", io.EOF.Error(), w)
}

func testParseBodyFieldByBodyType(t *testing.T, bt BodyType, s string) {
	body := &Body{}
	br := bufio.NewReader(strings.NewReader(s))
	w := func(isChunkHeader bool, data []byte) (int, error) {
		return 0, nil
	}
	_, err := body.Parse(br, bt, int64(len(s)), w)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func testParseBodyFieldWithErrorBody(t *testing.T, bt BodyType, s, expErr string, w BodyWrapper) {
	body := &Body{}
	br := bufio.NewReader(strings.NewReader(s))
	_, err := body.Parse(br, bt, int64(len(s)), w)
	if err == nil {
		t.Fatalf("expected error: %s", expErr)

	}
	if !strings.Contains(err.Error(), expErr) {
		t.Fatalf("expected error: %s, but get unexpected error: %s", expErr, err.Error())
	}
}
