package client

import (
	"bufio"
	"io"
	"testing"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/bytebufferpool"
)

// test write request line
func TestWriteRequestLine(t *testing.T) {
	w := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	bw := bPool.AcquireWriter(w)
	method := ""
	for i := 0; i < 10000; i++ {
		method += "G"
	}
	hostwithport := ""
	for i := 0; i < 10000; i++ {
		hostwithport += "G"
	}
	hostwithport += ".0.0.0:8080"

	path := ""
	for i := 0; i < 10000; i++ {
		path += "/"
	}

	protocol := ""
	for i := 0; i < 10000; i++ {
		protocol += "HTTP/1.1"
	}

	testWriteRequestLine(t, bw, false, nil, "GET", "127.0.0.1:8080", "/", "HTTP/1.1")

	bw.Reset(w)

	testWriteRequestLine(t, bw, true, nil, "GET", "127.0.0.1:8080", "/", "HTTP/1.1")

	bw.Reset(w)

	testWriteRequestLine(t, nil, true, errNilBufioWriter, "GET", "127.0.0.1:8080", "/", "HTTP/1.1")
	bw.Reset(w)

	testWriteRequestLine(t, bw, true, io.ErrShortBuffer, method, "127.0.0.1:8080", "/", "HTTP/1.1")
	bw.Reset(w)

	testWriteRequestLine(t, bw, true, io.ErrShortBuffer, "GET", hostwithport, "/", "HTTP/1.1")
	bw.Reset(w)

	testWriteRequestLine(t, bw, true, io.ErrShortBuffer, "GET", "127.0.0.1:8080", path, "HTTP/1.1")
	bw.Reset(w)

	testWriteRequestLine(t, bw, true, io.ErrShortBuffer, "GET", "127.0.0.1:8080", path, protocol)
	defer bPool.ReleaseWriter(bw)
}

func testWriteRequestLine(t *testing.T, bw *bufio.Writer, fullURL bool, expErr error, method, hostwithport, uri, protocol string) {
	n, err := writeRequestLine(bw, fullURL, []byte(method), hostwithport, []byte(uri), []byte(protocol))
	if err != nil {
		if err != expErr {
			t.Fatalf("Expected error is %s, but get unexpected errror: %s", expErr, err.Error())
		}
	} else {
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}

		if bw.Buffered() != n {
			t.Fatal("Write data error")
		}
	}
}
