package client

import (
	"io"
	"testing"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/bytebufferpool"
)

// test write request line
func TestWriteRequestLine(t *testing.T) {
	var err error
	w := bytebufferpool.MakeFixedSizeByteBuffer(100)
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	bw := bPool.AcquireWriter(w)
	n, err := writeRequestLine(bw, false, []byte("GET"), "127.0.0.1:8080", []byte("/"), []byte("HTTP/1.1"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if bw.Buffered() != n {
		t.Fatal("Write data error")
	}
	bw.Reset(w)

	n, err = writeRequestLine(bw, true, []byte("GET"), "127.0.0.1:8080", []byte("/"), []byte("HTTP/1.1"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}

	if bw.Buffered() != n {
		t.Fatal("Write data error")
	}
	bw.Reset(w)

	n, err = writeRequestLine(bw, true, []byte("GET"), "127.0.0.1:8080", []byte("/"), []byte("HTTP/1.1"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if bw.Buffered() != n {
		t.Fatal("Write data error")
	}
	bw.Reset(w)

	_, err = writeRequestLine(nil, false, []byte("GET"), "127.0.0.1:8080", []byte("/"), []byte("HTTP/1.1"))
	if err != errNilBufioWriter {
		t.Fatalf("Expected error is nil pool, but get unexpected errror: %s", err.Error())
	}
	bw.Reset(w)

	method := ""
	for i := 0; i < 10000; i++ {
		method += "G"
	}
	n, err = writeRequestLine(bw, false, []byte(method), "", nil, nil)
	if err != io.ErrShortBuffer {
		t.Fatalf("Expected error is nil pool, but get unexpected error: %s", err.Error())
	}
	if n > 4096 {
		t.Fatal("Should not write all data in bufio writer")
	}
	bw.Reset(w)

	hostwithport := ""
	for i := 0; i < 10000; i++ {
		hostwithport += "G"
	}
	hostwithport += ".0.0.0:8080"
	n, err = writeRequestLine(bw, false, []byte("GET"), hostwithport, []byte("/"), []byte("HTTP/1.1"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if n > 4096 {
		t.Fatal("Should not write all data in bufio writer")
	}
	bw.Reset(w)

	path := ""
	for i := 0; i < 10000; i++ {
		path += "/"
	}
	n, err = writeRequestLine(bw, false, []byte("GET"), "127.0.0.1:8080", []byte(path), []byte("HTTP/1.1"))
	if err != io.ErrShortBuffer {
		t.Fatalf("Expected error is nil pool, but get unexpected error: %s", err.Error())
	}
	if n > 4096 {
		t.Fatal("Should not write all data in bufio writer")
	}
	bw.Reset(w)

	protocol := ""
	for i := 0; i < 10000; i++ {
		protocol += "HTTP/1.1"
	}
	n, err = writeRequestLine(bw, false, []byte("GET"), "127.0.0.1:8080", []byte("/"), []byte(protocol))
	if err != io.ErrShortBuffer {
		t.Fatalf("Expected error is nil pool, but get unexpected error: %s", err.Error())
	}
	if n > 4096 {
		t.Fatal("Should not write all data in bufio writer")
	}

	defer bPool.ReleaseWriter(bw)
}
