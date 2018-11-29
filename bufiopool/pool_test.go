package bufiopool

import (
	"io"
	"strings"
	"testing"

	"github.com/haxii/fastproxy/bytebufferpool"
)

func TestBufioPool(t *testing.T) {
	newPool := New(1, 1)
	nReader := strings.NewReader("123")
	for i := 0; i < 5; i++ {
		nr := newPool.AcquireReader(nReader)
		if nr.Buffered() != 0 {
			t.Fatal("Bufiopool can't acquire an empty reader")
		}
		newByte := make([]byte, 10)
		result, err := nr.Read(newByte)
		if err != nil && err != io.EOF {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		if i > 0 && result != 0 {
			t.Fatal("Bufiopool can't acquire an empty reader")
		}
		newPool.ReleaseReader(nr)
		result, err = nr.Read(newByte)
		if err != nil && err != io.EOF {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		if result != 0 {
			t.Fatal("Bufiopool can't release a reader")
		}
	}

	newWriter := bytebufferpool.Get()
	newWriter.Set([]byte("123"))
	for i := 0; i < 5; i++ {
		nw := newPool.AcquireWriter(newWriter)
		if nw.Buffered() != 0 {
			t.Fatal("Bufiopool can't acquire an empty writer")
		}
		_, err := nw.WriteString("123")
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		if nw.Buffered() != 3 {
			t.Fatal("Bufiopool can't acquire a writer")
		}
		newPool.ReleaseWriter(nw)
	}
	var a string
	for i := 0; i < 5000; i++ {
		a += "t"
	}
	largeReader := strings.NewReader(a)
	nr := newPool.AcquireReader(largeReader)
	if nr.Buffered() != 0 {
		t.Fatal("expected buffer is 0")
	}
	_, err := nr.Peek(1)
	if err != nil {
		t.Fatal("expected peek error")
	}
	if nr.Buffered() != 4096 {
		t.Fatal("expected buffer is 4096")
	}

	largeWriter := bytebufferpool.Get()
	nw := newPool.AcquireWriter(largeWriter)
	if nw.Buffered() != 0 {
		t.Fatal("expected buffer is 0")
	}
	_, err = nw.Write([]byte(a))
	if err != nil {
		t.Fatal("expected Write error")
	}
	if nw.Buffered() != 0 {
		t.Fatal("expected buffer is 0")
	}
}
