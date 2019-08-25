package plugin

import (
	"bytes"
	"context"
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

// HandleFunc for http and bumped https
type HandleFunc func(*RequestConnInfo, *uri.URI, *RequestHeader) (*HijackedRequest, *HijackedResponse)

// HandleSSLFunc for https tunnels
type HandleSSLFunc func(*RequestConnInfo) *HijackedRequest

type HijackHandler struct {
	// routers
	sslRouter SSLRouters
	router    Routers

	// default handlers
	BlockByDefault    bool
	DefaultSuperProxy *superproxy.SuperProxy
	DefaultDial       func(addr string) (net.Conn, error)
	DefaultDialTLS    func(addr string, tlsConfig *tls.Config) (net.Conn, error)

	// hijackers
	RewriteHost          func(connInfo *RequestConnInfo) (newHost, newPort string)
	ShouldMakeTunnel     func(connInfo *RequestConnInfo, header http.Header, rawHeader []byte) bool
	SSLBump              func(connInfo *RequestConnInfo) bool
	RewriteTLSServerName func(connInfo *RequestConnInfo) string
}

// Add add a handler for http and bumped https connections
func (h *HijackHandler) Add(method, host, path string, handle HandleFunc) {
	h.router.Set(method, host, path, handle)
}

// AddSSL add a handler for https tunnels
func (h *HijackHandler) AddSSL(host string, handle HandleSSLFunc) {
	h.sslRouter.Set(host, handle)
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
	InspectWriter  ResponseWriter // used by HijackedResponseTypeInspect
	OverrideReader io.ReadCloser  // used by HijackedResponseTypeOverride
}

// Hijacker is handler implementation of proxy/hijacker
type Hijacker struct {
	connInfo RequestConnInfo
	uri      uri.URI

	requestHeader RequestHeader

	superProxy *superproxy.SuperProxy
	handler    *HijackHandler

	hijackedReq  *HijackedRequest
	hijackedResp *HijackedResponse
}

func (h *Hijacker) init(clientAddr net.Addr, isHTTPS bool, host, port string, handler *HijackHandler) {
	h.connInfo.reset()
	h.requestHeader.reset()

	h.connInfo.clientAddr = clientAddr
	h.connInfo.isHTTPS = isHTTPS
	h.connInfo.host = host
	h.connInfo.port = port
	if isHTTPS {
		h.uri.Parse(false, []byte("https://"+h.connInfo.host+":"+h.connInfo.port))
	} else {
		h.uri.Parse(false, []byte("http://"+h.connInfo.host+":"+h.connInfo.port))
	}
	h.superProxy = nil
	h.handler = handler
	h.hijackedReq = nil
	h.hijackedResp = nil
}

func (h *Hijacker) RewriteHost() (newHost, newPort string) {
	if h.handler != nil {
		if h.handler.RewriteHost != nil {
			newHost, h.connInfo.port = h.handler.RewriteHost(&h.connInfo)
			if !strings.EqualFold(newHost, h.connInfo.host) {
				h.connInfo.host = newHost
			}
			h.uri.ChangeHost(h.connInfo.host + ":" + h.connInfo.port)
		}
	}
	return h.connInfo.Host(), h.connInfo.Port()
}

func (h *Hijacker) OnConnect(header http.Header, rawHeader []byte) bool {
	if h.handler != nil {
		if h.handler.ShouldMakeTunnel != nil {
			return h.handler.ShouldMakeTunnel(&h.connInfo, header, rawHeader)
		}
	}
	return true
}

func (h *Hijacker) SSLBump() bool {
	if h.handler != nil {
		if h.handler.SSLBump != nil {
			h.connInfo.sslBump = h.handler.SSLBump(&h.connInfo)
		}
	}
	return h.connInfo.SSLBump()
}

func (h *Hijacker) RewriteTLSServerName(serverName string) string {
	h.connInfo.tlsServerName = serverName
	if h.handler != nil {
		if h.handler.RewriteTLSServerName != nil {
			h.connInfo.tlsServerName = h.handler.RewriteTLSServerName(&h.connInfo)
		}
	}
	return h.connInfo.TLSServerName()
}

func (h *Hijacker) BeforeRequest(method, path []byte, httpHeader http.Header,
	rawHeader []byte) (newPath, newRawHeader []byte) {
	h.connInfo.method = string(method)
	if h.handler != nil {
		h.uri.ChangePathWithFragment(path)
		pathOnly := h.uri.Path()
		handleFunc, _ := h.handler.router.GetHandleFunc(string(method), h.connInfo.host, string(pathOnly))
		if handleFunc != nil {
			h.requestHeader.rawHeader = rawHeader
			h.hijackedReq, h.hijackedResp = handleFunc(&h.connInfo, &h.uri, &h.requestHeader)
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
	// for https tunnel connections, BeforeRequest is not called, call the handler here
	if !h.connInfo.SSLBump() && h.handler != nil {
		handleSSLFunc := h.handler.sslRouter.GetHandleFunc(h.connInfo.Host())
		if handleSSLFunc != nil {
			h.hijackedReq = handleSSLFunc(&h.connInfo)
		}
	}
	if h.hijackedReq != nil {
		return h.hijackedReq.ResolvedIP
	}
	return nil
}

func (h *Hijacker) SuperProxy() *superproxy.SuperProxy {
	if h.hijackedReq != nil {
		return h.hijackedReq.SuperProxy
	}
	if h.handler != nil {
		return h.handler.DefaultSuperProxy
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

func (h *Hijacker) HijackResponse() io.ReadCloser {
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
	if h.handler != nil {
		return h.handler.DefaultDial
	}
	return nil
}

func (h *Hijacker) DialTLS() func(addr string, tlsConfig *tls.Config) (net.Conn, error) {
	if h.hijackedReq != nil {
		return h.hijackedReq.DialTLS
	}
	if h.handler != nil {
		return h.handler.DefaultDialTLS
	}
	return nil
}

func (Hijacker) OnRequest(path []byte, header http.Header, rawHeader []byte) io.WriteCloser {
	return nil
}

func (h *Hijacker) OnResponse(statusLine http.ResponseLine,
	header http.Header, rawHeader []byte) io.WriteCloser {
	if h.hijackedResp != nil {
		if h.hijackedResp.ResponseType == HijackedResponseTypeInspect &&
			h.hijackedResp.InspectWriter != nil {
			if err := h.hijackedResp.InspectWriter.WriteHeader(statusLine, header, rawHeader); err != nil {
				// write header encountered an error, close it
				h.hijackedResp.InspectWriter.Close()
				// TODO log error
				return nil
			}
			return h.hijackedResp.InspectWriter
		}
	}
	return nil
}

func (h *Hijacker) OnFinish() {
}

type ResponseWriter interface {
	WriteHeader(statusLine http.ResponseLine, header http.Header, rawHeader []byte) error
	io.WriteCloser
}

type RequestConnInfo struct {
	clientAddr net.Addr

	isHTTPS       bool
	host, port    string
	sslBump       bool
	tlsServerName string

	method string

	Context context.Context
}

func (i *RequestConnInfo) reset() {
	i.clientAddr = nil
	i.isHTTPS = false
	i.host = ""
	i.port = ""
	i.sslBump = false
	i.tlsServerName = ""
	i.method = ""
	i.Context = nil
}

func (i *RequestConnInfo) ClientAddr() net.Addr {
	return i.clientAddr
}

func (i *RequestConnInfo) IsHTTPS() bool {
	return i.isHTTPS
}

func (i *RequestConnInfo) Host() string {
	return i.host
}

func (i *RequestConnInfo) SSLBump() bool {
	return i.sslBump
}

func (i *RequestConnInfo) TLSServerName() string {
	return i.tlsServerName
}

func (i *RequestConnInfo) Method() string {
	return i.method
}

func (i *RequestConnInfo) Port() string {
	return i.port
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
