package util

import (
	"bufio"
	"errors"
	"io"

	"github.com/balinor2017/fastproxy/bytebufferpool"
)

var (
	errEmptyHexNum    = errors.New("empty hex number")
	errTooLargeHexNum = errors.New("too large hex number")
)

// ReadHexInt read hex from r then return it as well as put result in buffer
func ReadHexInt(r *bufio.Reader, buffer *bytebufferpool.ByteBuffer) (int, error) {
	n := 0
	i := 0
	var k int
	for {
		c, err := r.ReadByte()
		if err != nil {
			if err == io.EOF && i > 0 {
				return n, nil
			}
			return -1, err
		}
		if buffer != nil {
			if e := buffer.WriteByte(c); e != nil {
				return -1, e
			}
		}
		k = int(hex2intTable[c])
		if k == 16 {
			if i == 0 {
				return -1, errEmptyHexNum
			}
			r.UnreadByte()
			if buffer != nil {
				buffer.B = buffer.B[:buffer.Len()-1]
			}
			return n, nil
		}
		if i >= maxHexIntChars {
			return -1, errTooLargeHexNum
		}
		n = (n << 4) | k
		i++
	}
}

var hex2intTable = func() []byte {
	b := make([]byte, 255)
	for i := byte(0); i < 255; i++ {
		c := byte(16)
		if i >= '0' && i <= '9' {
			c = i - '0'
		} else if i >= 'a' && i <= 'f' {
			c = i - 'a' + 10
		} else if i >= 'A' && i <= 'F' {
			c = i - 'A' + 10
		}
		b[i] = c
	}
	return b
}()
