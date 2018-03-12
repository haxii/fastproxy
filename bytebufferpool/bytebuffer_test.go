package bytebufferpool

import (
	"testing"
	"time"
)

func TestByteBufferGetAndPutSerial(t *testing.T) {
	testByteBufferGetAndPut(t)
}

func TestByteBufferGetAndPutConcurrent(t *testing.T) {
	concurrency := 10
	ch := make(chan struct{}, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			testByteBufferGetAndPut(t)
			ch <- struct{}{}
		}()
	}

	for i := 0; i < concurrency; i++ {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("timeout!")
		}
	}
}

func testByteBufferGetAndPut(t *testing.T) {
	for i := 0; i < 5; i++ {
		b := Get()
		b.B = append(b.B, "num "...)
		expectedS := "num "
		if string(b.B) != expectedS {
			t.Fatalf("unexpected result: %q. Expecting %q", b.B, expectedS)
		}
		Put(b)
	}
}
