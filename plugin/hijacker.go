package plugin

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/textproto"
	"strings"
	"sync"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/bytebufferpool"
	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/proxy"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/uri"
)

type HijackHandler struct {
	router               Routers
	BlockByDefault       bool
	RewriteHost          func(host, port string) (newHost, newPort string)
	SSLBump              func(host string) bool
	RewriteTLSServerName func(serverName string) string
}

type HandleFunc func(*uri.URI, *RequestHeader) (*HijackedRequest, *HijackedResponse)

func (h *HijackHandler) Add(method, host, path string, handle HandleFunc) {
	h.router.Set(method, host, path, handle)
}

type HijackerPool struct {
	pool    sync.Pool
	Handler HijackHandler
}

func (p *HijackerPool) Get(clientAddr net.Addr, isHTTPS bool, host, port string) proxy.Hijacker {
	v := p.pool.Get()
	var h *Hijacker
	if v == nil {
		h = &Hijacker{}
	} else {
		h = v.(*Hijacker)
	}
	h.init(clientAddr, isHTTPS, host, port, &p.Handler)
	return h
}

func (p *HijackerPool) Put(h proxy.Hijacker) {
	if h == nil {
		return
	}
	hijacker := h.(*Hijacker)
	hijacker.OnFinish()
	p.pool.Put(h)
}

type HijackedResponseType int

const (
	HijackedResponseTypeBlock HijackedResponseType = iota
	HijackedResponseTypeInspect
	HijackedResponseTypeOverride
)

type HijackedRequest struct {
	OverridePath   []byte
	OverrideHeader []byte
	ResolvedIP     net.IP
	SuperProxy     *superproxy.SuperProxy
	Dial           func(addr string) (net.Conn, error)
	DialTLS        func(addr string, tlsConfig *tls.Config) (net.Conn, error)
}

type HijackedResponse struct {
	ResponseType   HijackedResponseType
	InspectWriter  io.Writer // used by HijackedResponseTypeInspect
	OverrideReader io.Reader // used by HijackedResponseTypeOverride
}

// Hijacker is handler implementation of proxy/hijacker
type Hijacker struct {
	clientAddr net.Addr

	isHTTPS    bool
	host, port string
	uri        uri.URI

	requestHeader RequestHeader

	superProxy *superproxy.SuperProxy
	handler    *HijackHandler

	hijackedReq  *HijackedRequest
	hijackedResp *HijackedResponse
}

func (h *Hijacker) init(clientAddr net.Addr, isHTTPS bool, host, port string, handler *HijackHandler) {
	h.clientAddr = clientAddr
	h.isHTTPS = isHTTPS
	h.host = host
	h.port = port
	if isHTTPS {
		h.uri.Parse(false, []byte("https://"+h.host+":"+h.port))
	} else {
		h.uri.Parse(false, []byte("http://"+h.host+":"+h.port))
	}
	h.requestHeader.reset()
	h.superProxy = nil
	h.handler = handler
	h.hijackedReq = nil
	h.hijackedResp = nil
}

func (h *Hijacker) RewriteHost() (newHost, newPort string) {
	if h.handler != nil {
		if h.handler.RewriteHost != nil {
			newHost, h.port = h.handler.RewriteHost(h.host, h.port)
			if !strings.EqualFold(newHost, h.host) {
				h.host = newHost
			}
			h.uri.ChangeHost(h.host + ":" + h.port)
		}
	}
	return h.host, h.port
}

func (h *Hijacker) SSLBump() bool {
	if h.handler != nil {
		if h.handler.SSLBump != nil {
			return h.handler.SSLBump(h.host)
		}
	}
	return false
}

func (h *Hijacker) RewriteTLSServerName(serverName string) string {
	if h.handler != nil {
		if h.handler.SSLBump != nil {
			return h.handler.RewriteTLSServerName(serverName)
		}
	}
	return serverName
}

func (h *Hijacker) BeforeRequest(method, path []byte, httpHeader http.Header,
	rawHeader []byte) (newPath, newRawHeader []byte) {
	if h.handler != nil {
		h.uri.ChangePathWithFragment(path)
		pathOnly := h.uri.Path()
		handleFunc, _ := h.handler.router.GetHandleFunc(string(method), h.host, string(pathOnly))
		if handleFunc != nil {
			h.requestHeader.rawHeader = rawHeader
			h.hijackedReq, h.hijackedResp = handleFunc(&h.uri, &h.requestHeader)
		}
	}

	if h.hijackedReq != nil {
		newPath = h.hijackedReq.OverridePath
		newRawHeader = h.hijackedReq.OverrideHeader
	}
	if newPath == nil {
		newPath = path
	}

	return newPath, newRawHeader
}

func (h *Hijacker) Resolve() net.IP {
	if h.hijackedReq != nil {
		return h.hijackedReq.ResolvedIP
	}
	return nil
}

func (h *Hijacker) SuperProxy() *superproxy.SuperProxy {
	if h.hijackedReq != nil {
		return h.hijackedReq.SuperProxy
	}
	return nil
}

func (h *Hijacker) Block() bool {
	if h.hijackedResp != nil {
		return h.hijackedResp.ResponseType == HijackedResponseTypeBlock
	}
	if h.handler != nil {
		return h.handler.BlockByDefault
	}
	return false
}

func (h *Hijacker) HijackResponse() io.Reader {
	if h.hijackedResp != nil {
		if h.hijackedResp.ResponseType == HijackedResponseTypeOverride {
			return h.hijackedResp.OverrideReader
		}
	}
	return nil
}

func (h *Hijacker) Dial() func(addr string) (net.Conn, error) {
	if h.hijackedReq != nil {
		return h.hijackedReq.Dial
	}
	return nil
}

func (h *Hijacker) DialTLS() func(addr string, tlsConfig *tls.Config) (net.Conn, error) {
	if h.hijackedReq != nil {
		return h.hijackedReq.DialTLS
	}
	return nil
}

func (Hijacker) OnRequest(path []byte, header http.Header, rawHeader []byte) io.Writer {
	return nil
}

func (h *Hijacker) OnResponse(statusLine http.ResponseLine,
	header http.Header, rawHeader []byte) io.Writer {
	if h.hijackedResp != nil {
		if h.hijackedResp.ResponseType == HijackedResponseTypeInspect &&
			h.hijackedResp.InspectWriter != nil {
			h.hijackedResp.InspectWriter.Write(statusLine.GetResponseLine())
			h.hijackedResp.InspectWriter.Write(rawHeader)
			return h.hijackedResp.InspectWriter
		}
	}
	return nil
}

func (h *Hijacker) OnFinish() {
}

// RequestHeader MIME Header wrapper, offers get key and raw header method
type RequestHeader struct {
	mimeHeader textproto.MIMEHeader
	rawHeader  []byte
}

func (h *RequestHeader) reset() {
	h.mimeHeader = nil
	h.rawHeader = nil
}

var requestHeaderBufioPool = bufiopool.New(128*1024, 4096)

func (h *RequestHeader) Get(key string) string {
	if h.mimeHeader == nil { // lazy init
		bytebufferpool.Get()
		headerReader := bytes.NewReader(h.rawHeader)
		headerBufioReader := requestHeaderBufioPool.AcquireReader(headerReader)
		defer requestHeaderBufioPool.ReleaseReader(headerBufioReader)
		headerTextProtoReader := textproto.NewReader(headerBufioReader)
		h.mimeHeader, _ = headerTextProtoReader.ReadMIMEHeader()
	}
	if h.mimeHeader == nil {
		return ""
	}
	return h.mimeHeader.Get(key)
}

func (h *RequestHeader) RawHeader() []byte {
	return h.rawHeader
}
