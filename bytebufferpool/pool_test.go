package bytebufferpool

import (
	"testing"
)

func TestByteBufferPoolPutAndGet(t *testing.T) {
	newPool := &Pool{}
	for i := 0; i < 10; i++ {
		b := newPool.Get()
		if b.String() == "123" {
			t.Fatal("Pool get and put error")
		}
		b.SetString("123")
		newPool.Put(b)
	}
}
