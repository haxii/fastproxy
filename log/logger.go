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
	Info(format string, v ...interface{})
	//Error nil client means this is a server internal error
	Error(client net.Addr, err error, format string, v ...interface{})
}

//DefaultLogger default logger based on std logger
type DefaultLogger struct{}

//Info log info
func (l *DefaultLogger) Info(format string, v ...interface{}) {
	log.Printf("[ INFO ] "+format, v...)
}

//Error log error
func (l *DefaultLogger) Error(client net.Addr, err error, format string, v ...interface{}) {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	clientAddr := ""
	if client != nil {
		clientAddr = client.String()
	}
	log.Printf("[ ERROR "+clientAddr+" : "+errMsg+" ]"+format, v...)
}
