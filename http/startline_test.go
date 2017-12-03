package http

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRespLine(t *testing.T) {
	testRespLineParse(t, "", io.EOF, "", 0, "")
	testRespLineParse(t, "HTTP/1.1 200 OK\r\n", nil, "HTTP/1.1", 200, "OK")
	testRespLineParse(t, "HTTP/1.1 200 OK\n", nil, "HTTP/1.1", 200, "OK")
	testRespLineParse(t, "HTTP/1.1 200 OK", io.EOF, "", 0, "")
	testRespLineParse(t, "HTTP/1.1\r\n", errRespLineNOProtocol, "", 0, "")
	testRespLineParse(t, "HTTP/1.1 \r\n", errRespLineNOStatusCode, "HTTP/1.1", 0, "")
	testRespLineParse(t, "HTTP/1.1 200\r\n", errRespLineNOStatusCode, "HTTP/1.1", 0, "")
	testRespLineParse(t, "HTTP/1.1 200 \r\n", nil, "HTTP/1.1", 200, "")
	testRespLineParse(t, "HTTP/1.1 OK \r\n", errors.New("fail to parse status status code"), "HTTP/1.1", 0, "")

}

func testRespLineParse(t *testing.T, line string, expErr error, expProtocol string, expCode int, expMsg string) {
	resp := &ResponseLine{}
	err := resp.Parse(bufio.NewReader(strings.NewReader(line)))
	if err != nil {
		if expErr == nil {
			t.Fatalf("unexpected error %s, expecting nil", err)
		}
		if !strings.Contains(err.Error(), expErr.Error()) {
			t.Fatalf("unexpected error %s, expecting %s", err, expErr)
		}
	} else if expErr != nil {
		t.Fatalf("unexpected nil error, expecting error %s,", expErr)
	}

	if !bytes.Equal(resp.GetProtocol(), []byte(expProtocol)) {
		t.Fatalf("unexpected protocol %s, expecting %s,", resp.GetProtocol(), expProtocol)
	}
	if resp.GetStatusCode() != expCode {
		t.Fatalf("unexpected status code %d, expecting %d,", resp.GetStatusCode(), expCode)
	}
	if !bytes.Equal(resp.GetStatusMessage(), []byte(expMsg)) {
		t.Fatalf("unexpected status msg %s, expecting %s,", resp.GetStatusMessage(), expMsg)
	}
}
