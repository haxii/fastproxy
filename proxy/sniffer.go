package proxy

import (
	"fmt"
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
	GetRequestWriter(uri []byte, header header.Header) io.Writer
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

func (s *basicSniffer) GetRequestWriter(uri []byte, header header.Header) io.Writer {
	fmt.Printf(`
************************
addr:%s
************************
uri:%s
************************
content length:%d
************************
`,
		s.clientAddr, uri, header.ContentLength())
	return os.Stdout
}

func (s *basicSniffer) GetResponseWriter(statusCode int, header header.Header) io.Writer {
	fmt.Printf(`
************************
addr:%s
************************
status code:%d
************************
content length:%d
************************
`,
		s.clientAddr, statusCode, header.ContentLength())
	return os.Stdout
}
