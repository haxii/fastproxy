package uri

import "bytes"

//URI http URI helper
type URI struct {
	scheme []byte
	host   []byte
	port   uint16

	pathWithQueryFragment []byte

	hostWithPort string
}

//HostWithPort host with port
func (uri *URI) HostWithPort() string {
	return uri.hostWithPort
}

//PathWithQueryFragment path with query and fragments
func (uri *URI) PathWithQueryFragment() []byte {
	return uri.pathWithQueryFragment
}

//Reset reset the request URI
func (uri *URI) Reset() {
	uri.host = uri.host[:0]
	uri.hostWithPort = ""
	uri.pathWithQueryFragment = uri.pathWithQueryFragment[:0]
	uri.scheme = uri.scheme[:0]
}

//Parse parse the request URI
//uri1: www.example.com:443
//uri2: /path/to/resource
//uri3.1: http://www.example.com
//uri3.2: http://www.example.com/path/to/resource
func (uri *URI) Parse(isConnect bool, reqURI []byte) {
	//uri1: https proxy reqest's hosts in the request uri
	if isConnect {
		uri.host = reqURI
		return
	}

	//scheme
	schemeEnd := bytes.Index(reqURI, []byte("//"))
	if schemeEnd <= 0 {
		//uri2: not a full uri, only relative path
		uri.pathWithQueryFragment = reqURI
		return
	}
	uri.scheme = reqURI[:schemeEnd]

	//host
	hostNameStart := schemeEnd + 2
	hostNameEnd := hostNameStart + bytes.IndexByte(reqURI[hostNameStart:], '/')
	if hostNameEnd <= hostNameStart {
		//uri3.1
		uri.host = reqURI[hostNameStart:]
		uri.pathWithQueryFragment = []byte{'/'}
	} else {
		//uri3.2
		uri.host = reqURI[hostNameStart:hostNameEnd]
		uri.pathWithQueryFragment = reqURI[hostNameEnd:]
	}
}

//FillHostWithPort ...
func (uri *URI) FillHostWithPort(isConnect bool) {
	hasPortFuncByte := func(host []byte) bool {
		return bytes.LastIndexByte(host, ':') >
			bytes.LastIndexByte(host, ']')
	}
	if len(uri.host) == 0 {
		return
	}
	uri.hostWithPort = string(uri.host)
	if !hasPortFuncByte(uri.host) {
		if isConnect {
			uri.hostWithPort += ":443"
		} else {
			uri.hostWithPort += ":80"
		}
	}
}
