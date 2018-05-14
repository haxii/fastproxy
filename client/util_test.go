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
	w := bytebufferpool.MakeFixedSizeByteBuffer(14)
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	bw := bPool.AcquireWriter(w)
	method := "GET"
	hostwithport := "127.0.0.1:8080"
	path := "/"
	protocol := "HTTP/1.1"

	testWriteRequestLine(t, bw, false, nil, method, hostwithport, path, protocol)

	bw.Reset(w)
	testWriteRequestLine(t, bw, true, nil, method, hostwithport, path, protocol)

	bw.Reset(w)
	testWriteRequestLine(t, nil, true, errNilBufioWriter, method, hostwithport, path, protocol)

	bw.Reset(w)
	testWriteRequestLine(t, bw, true, io.ErrShortBuffer, method+"ABCDEFGHIJKLMN", hostwithport, path, protocol)

	bw.Reset(w)
	testWriteRequestLine(t, bw, true, io.ErrShortBuffer, method, hostwithport+"ABCDEFGHIJKLMN", path, protocol)

	bw.Reset(w)
	testWriteRequestLine(t, bw, true, io.ErrShortBuffer, method, hostwithport, path+"ABCDEFGHIJKLMN", protocol)

	bw.Reset(w)
	testWriteRequestLine(t, bw, true, io.ErrShortBuffer, method, hostwithport, path, protocol+"ABCDEFGHIJKLMN")
	defer bPool.ReleaseWriter(bw)
}

func testWriteRequestLine(t *testing.T, bw *bufio.Writer, fullURL bool, expErr error, method, hostwithport, uri, protocol string) {
	n, err := writeRequestLine(bw, fullURL, []byte(method), hostwithport, []byte(uri), []byte(protocol))
	if err != nil {
		if err != expErr {
			t.Fatalf("Expected error is %s, but get unexpected error: %s", expErr, err.Error())
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
