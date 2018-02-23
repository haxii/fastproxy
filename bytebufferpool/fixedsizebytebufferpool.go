package bytebufferpool

import (
	"sync"
)

// FixedSizeByteBufferPool ...
type FixedSizeByteBufferPool struct {
	pool sync.Pool
}

// Get ...
func (p *FixedSizeByteBufferPool) Get() *FixedSizeByteBuffer {
	value := p.pool.Get()
	if value != nil {
		return value.(*FixedSizeByteBuffer)
	}
	return MakeByteBuffer(MaxSize)
}

// Put ...
func (p *FixedSizeByteBufferPool) Put(byteBuffer *FixedSizeByteBuffer) {
	p.pool.Put(byteBuffer)
}
