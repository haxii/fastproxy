package bytebufferpool

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

func TestByteBufferReadFrom(t *testing.T) {
	prefix := "foobar"
	expectedS := "asadfsdafsadfasdfisdsdfa"
	prefixLen := int64(len(prefix))
	expectedN := int64(len(expectedS))

	var bb ByteBuffer
	bb.WriteString(prefix)

	rf := (io.ReaderFrom)(&bb)
	for i := 0; i < 20; i++ {
		r := bytes.NewBufferString(expectedS)
		n, err := rf.ReadFrom(r)
		if n != expectedN {
			t.Fatalf("unexpected n=%d. Expecting %d. iteration %d", n, expectedN, i)
		}
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		bbLen := int64(bb.Len())
		expectedLen := prefixLen + int64(i+1)*expectedN
		if bbLen != expectedLen {
			t.Fatalf("unexpected byteBuffer length: %d. Expecting %d", bbLen, expectedLen)
		}
		for j := 0; j < i; j++ {
			start := prefixLen + int64(j)*expectedN
			b := bb.B[start : start+expectedN]
			if string(b) != expectedS {
				t.Fatalf("unexpected byteBuffer contents: %q. Expecting %q", b, expectedS)
			}
		}
	}
}

func TestByteBufferWriteTo(t *testing.T) {
	expectedS := "foobarbaz"
	var bb ByteBuffer
	bb.WriteString(expectedS[:3])
	bb.WriteString(expectedS[3:])

	wt := (io.WriterTo)(&bb)
	var w bytes.Buffer
	for i := 0; i < 10; i++ {
		n, err := wt.WriteTo(&w)
		if n != int64(len(expectedS)) {
			t.Fatalf("unexpected n returned from WriteTo: %d. Expecting %d", n, len(expectedS))
		}
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		s := string(w.Bytes())
		if s != expectedS {
			t.Fatalf("unexpected string written %q. Expecting %q", s, expectedS)
		}
		w.Reset()
	}
}

func TestByteBufferGetPutSerial(t *testing.T) {
	testByteBufferGetPut(t)
}

func TestByteBufferGetPutConcurrent(t *testing.T) {
	concurrency := 10
	ch := make(chan struct{}, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			testByteBufferGetPut(t)
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

func testByteBufferGetPut(t *testing.T) {
	for i := 0; i < 10; i++ {
		expectedS := fmt.Sprintf("num %d", i)
		b := Get()
		b.B = append(b.B, "num "...)
		b.B = append(b.B, fmt.Sprintf("%d", i)...)
		if string(b.B) != expectedS {
			t.Fatalf("unexpected result: %q. Expecting %q", b.B, expectedS)
		}
		Put(b)
	}
}

func testByteBufferGetString(t *testing.T) {
	for i := 0; i < 10; i++ {
		expectedS := fmt.Sprintf("num %d", i)
		b := Get()
		b.SetString(expectedS)
		if b.String() != expectedS {
			t.Fatalf("unexpected result: %q. Expecting %q", b.B, expectedS)
		}
		Put(b)
	}
}

func TestByteBufferGetStringSerial(t *testing.T) {
	testByteBufferGetString(t)
}

func TestByteBufferGetStringConcurrent(t *testing.T) {
	concurrency := 10
	ch := make(chan struct{}, concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			testByteBufferGetString(t)
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

func TestByteBufferCopy(t *testing.T) {
	b := Get()
	dst := Get()
	dst.Reset()
	s := "1234567"
	nReader := strings.NewReader(s)
	writen, err := b.Copy(dst, nReader)
	if err != nil {
		t.Fatalf("unexpected err: %s", err.Error())
	}
	if writen != 7 {
		t.Fatal("Copy size is wrong")
	}
	if !bytes.Equal(dst.Bytes(), []byte(s)) {
		t.Fatal("Copy content is wrong")
	}
}

func TestCopyWithIdleDuration(t *testing.T) {

	b := Get()
	b.Reset()
	src := GetSleepByteBuffer()
	dst := Get()
	dst.Reset()

	s := "hello world!"
	src.Write([]byte(s))
	src.SetTime(0)

	n, err := b.CopyWithIdleDuration(dst, src, 0)
	if err != nil {
		t.Fatalf("unexpected err: %s", err.Error())
	}
	if int(n) != src.Len() {
		t.Fatal("Copy size is wrong")
	}
	if !bytes.Equal(dst.Bytes(), src.Bytes()) {
		t.Fatal("Copy content is wrong")
	}

	dst.Reset()
	src.Reset()
	src.SetTime(1 * time.Second)
	n, err = b.CopyWithIdleDuration(dst, src, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected err: %s", err.Error())
	}
	if int(n) != src.Len() {
		t.Fatal("Copy size is wrong")
	}
	if !bytes.Equal(dst.Bytes(), src.Bytes()) {
		t.Fatal("Copy content is wrong")
	}

	dst.Reset()
	src.Reset()
	src.SetTime(4 * time.Second)
	n, err = b.CopyWithIdleDuration(dst, src, 1*time.Second)
	if err == nil {
		t.Fatal("expected err: idle time out")
	}
	if !strings.Contains(err.Error(), "idle time out") {
		t.Fatal("expected err: idle time out, but get unexpected error")
	}
}

type ByteBufferWithSleeping struct {
	B            []byte
	readIdleTime time.Duration
	used         int
	i            int
}

func (b *ByteBufferWithSleeping) Write(p []byte) (int, error) {
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

func (b *ByteBufferWithSleeping) SetTime(readIdle time.Duration) {
	b.readIdleTime = readIdle
}

func (b *ByteBufferWithSleeping) Read(p []byte) (int, error) {
	if b.i >= len(b.B) {
		return 0, io.EOF
	}
	time.Sleep(b.readIdleTime)
	n := copy(p, b.B[b.i:])
	b.i += n
	fmt.Println(n)
	return n, nil
}

func (b *ByteBufferWithSleeping) Bytes() []byte {
	return b.B
}

func (b *ByteBufferWithSleeping) Len() int {
	return b.i
}

func (b *ByteBufferWithSleeping) Reset() {
	b.i = 0
	b.used = 0
}

func GetSleepByteBuffer() *ByteBufferWithSleeping {
	return &ByteBufferWithSleeping{
		B:    make([]byte, 20),
		used: 0,
		i:    0,
	}
}
