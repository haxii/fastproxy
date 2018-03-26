package bufiopool

import (
	"bufio"
	"io"
	"sync"
)

// Pool buff io read and writer pool
type Pool struct {
	readBufferSize  int
	writeBufferSize int

	// pool for bytes reader & writer
	readerPool sync.Pool
	writerPool sync.Pool
}

const (
	// MinReadBufferSize default read size for buffer io
	MinReadBufferSize = 4096
	// MinWriteBufferSize default write size for buffer io
	MinWriteBufferSize = 4096
)

// New make a new buff io pool
// min read / write buffer size is set if they are
// smaller than MinReadBufferSize / MinWriteBufferSize
func New(readBufferSize, writeBufferSize int) *Pool {
	if readBufferSize < MinReadBufferSize {
		readBufferSize = MinReadBufferSize
	}
	if writeBufferSize < MinWriteBufferSize {
		writeBufferSize = MinWriteBufferSize
	}
	return &Pool{
		readBufferSize:  readBufferSize,
		writeBufferSize: writeBufferSize,
	}
}

// AcquireReader acquire a buffered reader based on net connection
func (p *Pool) AcquireReader(c io.Reader) *bufio.Reader {
	v := p.readerPool.Get()
	if v == nil {
		n := p.readBufferSize
		if n < MinReadBufferSize {
			n = MinReadBufferSize
		}
		return bufio.NewReaderSize(c, n)
	}
	r := v.(*bufio.Reader)
	r.Reset(c)
	return r
}

// ReleaseReader release a buffered reader
func (p *Pool) ReleaseReader(r *bufio.Reader) {
	p.readerPool.Put(r)
}

// AcquireWriter acquire a buffered writer based on net connection
func (p *Pool) AcquireWriter(c io.Writer) *bufio.Writer {
	v := p.writerPool.Get()
	if v == nil {
		n := p.writeBufferSize
		if n < MinWriteBufferSize {
			n = MinWriteBufferSize
		}
		return bufio.NewWriterSize(c, n)
	}
	bw := v.(*bufio.Writer)
	bw.Reset(c)
	return bw
}

// ReleaseWriter release a buffered writer
func (p *Pool) ReleaseWriter(bw *bufio.Writer) {
	p.writerPool.Put(bw)
}
