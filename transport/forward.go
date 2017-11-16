package transport

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/haxii/fastproxy/log"
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
func Forward(dst io.Writer, src io.Reader, l log.Logger, wg *sync.WaitGroup) {
	/*
		buffer := bytebufferpool.Get()
		defer bytebufferpool.Put(buffer)
		if _, err := buffer.Copy(dst, src); err != nil {
			errStr := err.Error()
			if !(strings.Contains(errStr, "broken pipe") ||
				strings.Contains(errStr, "reset by peer") ||
				strings.Contains(errStr, "i/o timeout")) {

			}
			l.Error(err, "Error copying to client")
		}
		fmt.Printf("%s\n", buffer.B)
		wg.Done()
	*/
}

//Forward2 forward remote and local connection
func Forward2(dst io.Writer, src bufio.Reader, l log.Logger, wg *sync.WaitGroup) {
	if _, err := src.WriteTo(dst); err != nil {
		errStr := err.Error()
		if !(strings.Contains(errStr, "broken pipe") ||
			strings.Contains(errStr, "reset by peer") ||
			strings.Contains(errStr, "i/o timeout")) {

		}
		l.Error(err, "Error copying to client")
	}
	wg.Done()
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
