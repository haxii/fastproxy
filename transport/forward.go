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

//Forward forward remote and local connection
func Forward(dst io.Writer, src io.Reader) error {
	buffer := bytebufferpool.Get()
	defer bytebufferpool.Put(buffer)
	var err error
	if _, e := buffer.Copy(dst, src); e != nil {
		errStr := e.Error()
		if !(strings.Contains(errStr, "broken pipe") ||
			strings.Contains(errStr, "reset by peer") ||
			strings.Contains(errStr, "i/o timeout")) {
			err = e
		}
	}
	return err
}

/*

Dial with cache is not stable enough to work on production mode

var defaultHostDialerPool = &HostDialerPool{
	MaxConnsPerHost:     connpool.DefaultMaxConnsPerHost,
	MaxIdleConnDuration: connpool.DefaultMaxIdleConnDuration,
}

//ConnHandler net connection handler
type ConnHandler func(*net.Conn, error) error

//DialTLSWithCache dial tls with cache
func DialTLSWithCache(host string, isTLS bool, serverName string, handler ConnHandler) error {
	return dialWithCache(host, true, serverName, handler)
}

//DialWithCache dial with cache
func DialWithCache(host string, handler ConnHandler) error {
	return dialWithCache(host, false, "", handler)
}

//dialTLSWithCache dial to host using conn pool
func dialWithCache(host string, isTLS bool, serverName string, handler ConnHandler) error {
	hostDialer := defaultHostDialerPool.Get(host, isTLS, serverName)
	conn, err := hostDialer.Dial()
	if err != nil {
		return handler(nil, err)
	}
	handlerErr := handler(conn.Get(), nil)
	if handlerErr != nil {
		hostDialer.Close(conn)
	} else {
		hostDialer.Release(conn)
	}
	return handlerErr
}

*/
