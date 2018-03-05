package bytebufferpool

import (
	"io"
)

// MaxSize default max size for byte buffer
var MaxSize = 32 * 1024

// FixedSizeByteBuffer provides fixed size byte buffer
//
// ByteBuffer may be used with functions appending data to the given []byte
// slice.
//
// Use Get for obtaining an empty byte buffer.
type FixedSizeByteBuffer struct {
	// B is a byte buffer to use in append-like workloads.
	B    []byte
	used int
}

// Bytes returns b.B, i.e. all the bytes accumulated in the buffer.
//
// The purpose of this function is bytes.Buffer compatibility.
func (b *FixedSizeByteBuffer) Bytes() []byte {
	return b.B[:b.used]
}

//Len returns the usage of fixed size byte buffer
func (b *FixedSizeByteBuffer) Len() int {
	return b.used
}

// Write implements io.Writer
func (b *FixedSizeByteBuffer) Write(p []byte) (int, error) {
	n := len(b.B) - b.used
	var err error
	var writingLength int
	if len(p) < n {
		writingLength = copy(b.B[b.used:], p)
		b.used += len(p)
		err = nil
	} else {
		writingLength = copy(b.B[b.used:], p[:n])
		err = io.ErrShortBuffer
		b.used = len(b.B)
	}
	return writingLength, err
}

// MakeByteBuffer get a fixed size ByteBuffer by default
func MakeByteBuffer(size int) *FixedSizeByteBuffer {
	var byteBuffer = FixedSizeByteBuffer{
		B:    make([]byte, size),
		used: 0,
	}
	return &byteBuffer
}

// Reset reset byteBuffer
func (b *FixedSizeByteBuffer) Reset() {
	b.used = 0
}
