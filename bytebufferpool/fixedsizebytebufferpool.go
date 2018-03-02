package bytebufferpool

import (
	"sync"
)

// FixedSizeByteBufferPool is a fixed size bytebuffer pool
type FixedSizeByteBufferPool struct {
	pool sync.Pool
}

// Get get a fixed size bytebuffer from pool
func (p *FixedSizeByteBufferPool) Get() *FixedSizeByteBuffer {
	value := p.pool.Get()
	if value != nil {
		return value.(*FixedSizeByteBuffer)
	}
	return MakeByteBuffer(MaxSize)
}

// Put put a bytebuffer into pool
func (p *FixedSizeByteBufferPool) Put(byteBuffer *FixedSizeByteBuffer) {
	p.pool.Put(byteBuffer)
}
