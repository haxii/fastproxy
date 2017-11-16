package proxy

import "github.com/haxii/fastproxy/log"

//Sniffer http sniffer
type Sniffer interface {
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
	return &logSniffer{log}
}

type logSniffer struct {
	log log.Logger
}

//ReqLine request line sniffer
func (s *logSniffer) ReqLine(l []byte) {
	s.log.Info("request line: %s", l)
}

//RespLine response line sniffer
func (s *logSniffer) RespLine(l []byte) {
	s.log.Info("response line: %s", l)
}

//Header header sniffer
func (s *logSniffer) Header(h []byte) {
	s.log.Info("http header: %s", h)
}

//Body body Sniffer
func (s *logSniffer) Body(b []byte) {
	s.log.Info("http body part: %s", b)
}
