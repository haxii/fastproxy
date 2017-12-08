package log

import (
	"log"
	"net"
)

//InfoWrapper log info wrapper
type InfoWrapper func(format string, v ...interface{})

//ErrorWrapper log error wrapper
type ErrorWrapper func(err error, format string, v ...interface{})

//Logger proxy logger, used for logging proxy info and errors
type Logger interface {
	Info(client net.Addr, format string, v ...interface{})
	Error(client net.Addr, err error, format string, v ...interface{})
}

//DefaultLogger default logger based on std logger
type DefaultLogger struct{}

//Info log info
func (l *DefaultLogger) Info(client net.Addr, format string, v ...interface{}) {
	log.Printf("[ INFO "+client.String()+" ] "+format, v...)
}

//Error log error
func (l *DefaultLogger) Error(client net.Addr, err error, format string, v ...interface{}) {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	log.Printf("[ ERROR "+client.String()+" : "+errMsg+" ]"+format, v...)
}

//DefaultProxyServerAddr used by Logger to log server related info and errors
var DefaultProxyServerAddr = &ProxyServerAddr{}

//ProxyServerAddr implements the net.Addr for proxy server
type ProxyServerAddr struct{}

//Network ...
func (*ProxyServerAddr) Network() string {
	return "TCP"
}

//String ...
func (*ProxyServerAddr) String() string {
	return "ProxyMGR"
}
