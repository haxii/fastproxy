package bytebufferpool

import (
	"io"
)

// MaxSize default max size for byte buffer
var MaxSize = 1024 * 1024

// FixedSizeByteBuffer provides byte buffer, which can be used for minimizing
// memory allocations.
//
// ByteBuffer may be used with functions appending data to the given []byte
// slice. See example code for details.
//
// Use Get for obtaining an empty byte buffer.
type FixedSizeByteBuffer struct {
	// B is a byte buffer to use in append-like workloads.
	// See example code for details.
	B    []byte
	Used int
}

// Bytes returns b.B, i.e. all the bytes accumulated in the buffer.
//
// The purpose of this function is bytes.Buffer compatibility.
func (b *FixedSizeByteBuffer) Bytes() []byte {
	return b.B[:b.Used]
}

// Write implements io.Writer - it appends p to ByteBuffer.B
func (b *FixedSizeByteBuffer) Write(p []byte) (int, error) {
	n := len(b.B) - b.Used
	var err error
	var writingLength int
	if len(p) < n {
		writingLength = copy(b.B[b.Used:], p)
		b.Used += len(p)
		err = nil
	} else {
		writingLength = copy(b.B[b.Used:], p[:n])
		err = io.ErrShortBuffer
		b.Used = len(b.B)
	}
	return writingLength, err
}

// MakeByteBuffer get a ByteBuffer by default
func MakeByteBuffer(size int) *FixedSizeByteBuffer {
	var byteBuffer = FixedSizeByteBuffer{
		B:    make([]byte, size),
		Used: 0,
	}
	return &byteBuffer
}

// Reset reset byteBuffer
func (b *FixedSizeByteBuffer) Reset() {
	b.Used = 0
}
