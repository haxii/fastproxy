package bufiopool

import (
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
			t.Fatal("Bufiopool can't acquire a empty reader")
		}
		newPool.ReleaseReader(nr)
	}

	newWriter := bytebufferpool.Get()
	newWriter.Set([]byte("123"))
	for i := 0; i < 5; i++ {
		nw := newPool.AcquireWriter(newWriter)
		if nw.Buffered() != 0 {
			t.Fatal("Bufiopool can't acquire a empty writer")
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
