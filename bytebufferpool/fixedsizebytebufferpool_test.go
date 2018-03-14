package bytebufferpool

import (
	"testing"
)

func TestFixedSizeByteBufferPool(t *testing.T) {
	fp := &FixedSizeByteBufferPool{}
	for i := 0; i < 10; i++ {
		fb := fp.Get()
		if fb.Len() != 0 {
			t.Fatal("Pool can't get an empty fixed size buffer")
		}
		_, err := fb.Write([]byte("123"))
		if err != nil {
			t.Fatalf("unexpected error: %s", err.Error())
		}
		fp.Put(fb)
	}
}