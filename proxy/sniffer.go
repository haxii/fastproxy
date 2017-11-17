package proxy

import (
	"io"
	"net"
	"os"

	"github.com/haxii/fastproxy/header"
)

//Sniffer http sniffer
type Sniffer interface {
	// InitWithClientAddress init with client address
	InitWithClientAddress(clientAddress net.Addr)
	// GetRequestWriter return a request writer based on uri & header
	GetRequestWriter(uri string, header header.Header) io.Writer
	// GetResponseWriter return a response writer based on status code & header
	GetResponseWriter(statusCode int, header header.Header) io.Writer
}

//NewDefaltBasicSniffer default std out based sniffer
func NewDefaltBasicSniffer() Sniffer {
	return &basicSniffer{}
}

type basicSniffer struct {
	clientAddr string
}

//InitWithClientAddress init with client address
func (s *basicSniffer) InitWithClientAddress(clientAddress net.Addr) {
	s.clientAddr = clientAddress.String()
}

func (s *basicSniffer) GetRequestWriter(uri string, header header.Header) io.Writer {
	return os.Stdout
}

func (s *basicSniffer) GetResponseWriter(statusCode int, header header.Header) io.Writer {
	return os.Stdout
}
