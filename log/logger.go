package log

import (
	"log"
	"net"
)

//Logger proxy logger, used for logging proxy info and errors
type Logger interface {
	Debug(client net.Addr, format string, v ...interface{})
	Info(client net.Addr, format string, v ...interface{})
	Error(client net.Addr, err error, format string, v ...interface{})
}

//DefaultLogger default logger based on std logger
type DefaultLogger struct{}

//Debug log info
func (l *DefaultLogger) Debug(client net.Addr, format string, v ...interface{}) {
	log.Printf("[ DEBUG "+client.String()+" ] "+format, v...)
}

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
