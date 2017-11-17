package proxy

import "github.com/haxii/fastproxy/log"
import "net"

//Sniffer http sniffer
type Sniffer interface {
	//InitWithClientAddress init with client address
	InitWithClientAddress(clientAddress net.Addr)
	//ReqLine request line sniffer
	ReqLine([]byte)
	//RespLine response line sniffer
	RespLine([]byte)
	//Header header sniffer
	Header([]byte)
	//Body body Sniffer
	Body([]byte)
}

//NewDefaltLogSniffer default log based sniffer
func NewDefaltLogSniffer(log log.Logger) Sniffer {
	return &logSniffer{log: log}
}

type logSniffer struct {
	clientAddr string
	log        log.Logger
}

func (s *logSniffer) InitWithClientAddress(clientAddress net.Addr) {
	s.clientAddr = clientAddress.String()
}

//ReqLine request line sniffer
func (s *logSniffer) ReqLine(l []byte) {
	s.log.Info("[%s]request line: %s", s.clientAddr, l)
}

//RespLine response line sniffer
func (s *logSniffer) RespLine(l []byte) {
	s.log.Info("[%s]response line: %s", s.clientAddr, l)
}

//Header header sniffer
func (s *logSniffer) Header(h []byte) {
	s.log.Info("[%s]http header: %s", s.clientAddr, h)
}

//Body body Sniffer
func (s *logSniffer) Body(b []byte) {
	s.log.Info("[%s]http body part: %s", s.clientAddr, b)
}
