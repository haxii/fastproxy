package uri

import (
	"bytes"
)

//URI http URI helper
type URI struct {
	isTLS bool

	full   []byte
	scheme []byte
	host   []byte

	path      []byte
	queries   []byte
	fragments []byte

	hostWithPort string

	pathWithQueryFragment       []byte
	pathWithQueryFragmentParsed bool
}

//Scheme ...
func (uri *URI) Scheme() []byte {
	return uri.scheme
}

//Host host specified in uri
func (uri *URI) Host() []byte {
	return uri.host
}

//PathWithQueryFragment ...
func (uri *URI) PathWithQueryFragment() []byte {
	if uri.pathWithQueryFragmentParsed {
		return uri.pathWithQueryFragment
	}
	if uri.isTLS {
		uri.pathWithQueryFragment = nil
		uri.pathWithQueryFragmentParsed = true
		return nil
	}
	if len(uri.host) == 0 {
		uri.pathWithQueryFragment = uri.full
	} else if hostIndex := bytes.Index(uri.full, uri.host); hostIndex > 0 {
		uri.pathWithQueryFragment = uri.full[hostIndex+len(uri.host):]
	}
	if len(uri.pathWithQueryFragment) == 0 {
		uri.pathWithQueryFragment = uri.path
	}
	uri.pathWithQueryFragmentParsed = true
	return uri.pathWithQueryFragment
}

//Path ...
func (uri *URI) Path() []byte {
	return uri.path
}

//Queries ...
func (uri *URI) Queries() []byte {
	return uri.queries
}

//Fragments ...
func (uri *URI) Fragments() []byte {
	return uri.fragments
}

//HostWithPort host with port
func (uri *URI) HostWithPort() string {
	return uri.hostWithPort
}

//Reset reset the request URI
func (uri *URI) Reset() {
	uri.isTLS = false
	uri.full = uri.full[:0]
	uri.host = uri.host[:0]
	uri.hostWithPort = ""
	uri.scheme = uri.scheme[:0]
	uri.path = uri.path[:0]
	uri.queries = uri.queries[:0]
	uri.fragments = uri.fragments[:0]
	uri.pathWithQueryFragment = uri.pathWithQueryFragment[:0]
	uri.pathWithQueryFragmentParsed = false
}

//Parse parse the request URI
func (uri *URI) Parse(isTLS bool, reqURI []byte) {
	uri.isTLS = isTLS
	if len(reqURI) == 0 {
		return
	}
	uri.Reset()
	uri.full = reqURI
	fragmentIndex := bytes.IndexByte(reqURI, '#')
	if fragmentIndex >= 0 {
		uri.fragments = reqURI[fragmentIndex:]
		uri.parseWithoutFragments(reqURI[:fragmentIndex])
	} else {
		uri.parseWithoutFragments(reqURI)
	}
	if !isTLS && len(uri.path) == 0 {
		uri.path = []byte("/")
	}
	if isTLS {
		uri.scheme = uri.scheme[:0]
		uri.path = uri.path[:0]
		uri.queries = uri.queries[:0]
		uri.fragments = uri.fragments[:0]
	}
	uri.fillHostWithPort(isTLS)
}

//parse uri with out fragments
func (uri *URI) parseWithoutFragments(reqURI []byte) {
	if len(reqURI) == 0 {
		return
	}
	queryIndex := bytes.IndexByte(reqURI, '?')
	if queryIndex >= 0 {
		uri.queries = reqURI[queryIndex:]
		uri.parseWithoutQueriesFragments(reqURI[:queryIndex])
	} else {
		uri.parseWithoutQueriesFragments(reqURI)
	}
}

//parse uri without queries and fragments
func (uri *URI) parseWithoutQueriesFragments(reqURI []byte) {
	if len(reqURI) == 0 {
		return
	}
	schemeEnd := getSchemeIndex(reqURI)
	if schemeEnd >= 0 {
		uri.scheme = reqURI[:schemeEnd]
		uri.parseWithoutSchemeQueriesFragments(reqURI[schemeEnd+1:])
	} else {
		uri.parseWithoutSchemeQueriesFragments(reqURI)
	}
}

//parse uri without scheme, queries and fragments
func (uri *URI) parseWithoutSchemeQueriesFragments(reqURI []byte) {
	//remove slashes begin with `//`
	if len(uri.scheme) > 0 && len(reqURI) >= 2 && reqURI[0] == '/' && reqURI[1] == '/' {
		slashIndex := 0
		for i, b := range reqURI {
			if b != '/' {
				break
			}
			slashIndex = i
		}
		reqURI = reqURI[slashIndex+1:]
	}
	if len(reqURI) == 0 {
		return
	}
	//only path
	if reqURI[0] == '/' {
		uri.path = reqURI
		return
	}
	//host with path
	hostNameEnd := bytes.IndexByte(reqURI, '/')
	if hostNameEnd > 0 {
		uri.host = reqURI[:hostNameEnd]
		uri.path = reqURI[hostNameEnd:]
	} else {
		uri.host = reqURI
	}
}

//getSchemeIndex (Scheme must be [a-zA-Z0-9]*)
func getSchemeIndex(rawurl []byte) int {
	for i := 0; i < len(rawurl); i++ {
		c := rawurl[i]
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9':
		case c == ':':
			if i == 0 {
				return 0
			}
			return i
		default:
			// we have encountered an invalid character,
			// so there is no valid scheme
			return -1
		}
	}
	return -1
}

//fillHostWithPort ...
func (uri *URI) fillHostWithPort(isTLS bool) {
	hasPortFuncByte := func(host []byte) bool {
		return bytes.LastIndexByte(host, ':') >
			bytes.LastIndexByte(host, ']')
	}
	if len(uri.host) == 0 {
		return
	}
	uri.hostWithPort = string(uri.host)
	if !hasPortFuncByte(uri.host) {
		if isTLS {
			uri.hostWithPort += ":443"
		} else {
			uri.hostWithPort += ":80"
		}
	}
}
