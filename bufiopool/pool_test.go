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
}
