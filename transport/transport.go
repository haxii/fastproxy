package transport

import (
	"crypto/tls"
	"io"
	"net"
	"strings"

	"github.com/haxii/fastproxy/bytebufferpool"
)

//DialTLS dial tls without pool
func DialTLS(addr string, tlsConfig *tls.Config) (net.Conn, error) {
	return dial(addr, true, tlsConfig)
}

//Dial dial without pool
func Dial(addr string) (net.Conn, error) {
	return dial(addr, false, nil)
}

// Forward forward remote and local connection
// It returns the number of bytes write to dst
// and the first error encountered while writing, if any.
func Forward(dst io.Writer, src io.Reader) (int64, error) {
	buffer := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer)
	var err, e error
	var wn int64
	if wn, e = buffer.Copy(dst, src); e != nil {
		errStr := e.Error()
		if !(strings.Contains(errStr, "broken pipe") ||
			strings.Contains(errStr, "reset by peer") ||
			strings.Contains(errStr, "i/o timeout")) {
			err = e
		}
	}
	return wn, err
}
