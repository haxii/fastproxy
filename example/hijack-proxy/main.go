package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/haxii/fastproxy/http"
	"github.com/haxii/fastproxy/plugin"
	"github.com/haxii/fastproxy/proxy"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/fastproxy/uri"
	"github.com/haxii/log"
)

func main() {
	hijackHandler := plugin.HijackHandler{
		BlockByDefault: false,
		RewriteHost: func(info *plugin.RequestConnInfo) (newHost, newPort string) {
			newHost = info.Host()
			newPort = info.Port()
			if strings.Contains(newHost, "postman-echo-via-proxy") {
				newHost = strings.Replace(newHost, "-via-proxy", "", -1)
				if info.Context == nil {
					info.Context = context.WithValue(context.Background(), "proxy", true)
				}
			}
			fmt.Printf("RewriteHost handler called %s:%s -> %s:%s \n",
				info.Host(), info.Port(), newHost, newPort)
			return newHost, newPort
		},
		SSLBump: func(info *plugin.RequestConnInfo) bool {
			fmt.Printf("SSLBump handler called %s:%s\n", info.Host(), info.Port())
			if strings.Contains(info.Host(), "postman-echo") {
				return false
			}
			return true
		},
		RewriteTLSServerName: func(info *plugin.RequestConnInfo) string {
			fmt.Println("RewriteTLSServerName handler called: ", info.TLSServerName())
			return info.TLSServerName()
		},
	}
	// matches curl -k -v -x 0.0.0.0:8082  https://httpbin.org/get
	// matches curl -v -x 0.0.0.0:8082  http://httpbin.org/get
	// doesn't match  http[s]://www.httpbin.org/get
	hijackHandler.Add("GET", "httpbin*", "/get", printResponseFunc)

	// hijacks www.baidu.com requests
	hijackHandler.Add("*", "www.baidu.com", "/*filepath", hijackEvilFunc)
	// block other baidu sites
	hijackHandler.Add("*", "*baidu*", "/*filepath", blockRequestFunc)

	// hijack postman-echo http and tunneled https
	// matches over proxy curl -k -v -x 0.0.0.0:8082 http[s]://postman-echo-via-proxy.com/get
	// matches over proxy curl -k -v -x 0.0.0.0:8082 http[s]://postman-echo-via-proxy.com/ip
	// matches without proxy curl -k -v -x 0.0.0.0:8082 http[s]://postman-echo.com/get
	// matches without proxy curl -k -v -x 0.0.0.0:8082 http[s]://postman-echo.com/ip
	hijackHandler.Add("*", "*postman-echo*", "/*filepath", hijackPostmanEchoFunc)
	hijackHandler.AddSSL("*postman-echo*", hijackPostmanEchoSSLFunc)

	p := proxy.Proxy{
		Logger:             &log.DefaultLogger{},
		ServerIdleDuration: time.Second * 30,
		HijackerPool:       &plugin.HijackerPool{Handler: hijackHandler},
	}
	panic(p.Serve("tcp", "0.0.0.0:8082"))
}

func printResponseFunc(info *plugin.RequestConnInfo, u *uri.URI,
	h *plugin.RequestHeader) (*plugin.HijackedRequest, *plugin.HijackedResponse) {
	fmt.Printf("printResponseFunc called, with Scheme %s Host %s, URL %s, User-Agent %s\n\n",
		u.Scheme(), u.HostInfo().HostWithPort(), u.PathWithQueryFragment(), h.Get("User-Agent"))
	return nil, &plugin.HijackedResponse{
		ResponseType:  plugin.HijackedResponseTypeInspect,
		InspectWriter: &respStdoutWriter{},
	}
}

func hijackEvilFunc(info *plugin.RequestConnInfo, u *uri.URI,
	h *plugin.RequestHeader) (*plugin.HijackedRequest, *plugin.HijackedResponse) {
	fmt.Printf("hijackEvilFunc called, with Scheme %s Host %s, URL %s, User-Agent %s\n\n",
		u.Scheme(), u.HostInfo().HostWithPort(), u.PathWithQueryFragment(), h.Get("User-Agent"))
	return nil, &plugin.HijackedResponse{
		ResponseType: plugin.HijackedResponseTypeOverride,
		OverrideReader: ioutil.NopCloser(
			strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 56\r\nConnection: close\r\n\r\n" +
				"You're blocked from visiting evil sites via this proxy.\n")),
	}
}

func blockRequestFunc(info *plugin.RequestConnInfo, u *uri.URI,
	h *plugin.RequestHeader) (*plugin.HijackedRequest, *plugin.HijackedResponse) {
	fmt.Printf("blockRequestFunc called, with Scheme %s Host %s, URL %s, User-Agent %s\n\n",
		u.Scheme(), u.HostInfo().HostWithPort(), u.PathWithQueryFragment(), h.Get("User-Agent"))
	return nil, &plugin.HijackedResponse{ResponseType: plugin.HijackedResponseTypeBlock}
}

func hijackPostmanEchoFunc(info *plugin.RequestConnInfo, u *uri.URI,
	h *plugin.RequestHeader) (*plugin.HijackedRequest, *plugin.HijackedResponse) {
	fmt.Printf("hijackPostmanEchoFunc called, with Scheme %s Host %s, URL %s, User-Agent %s\n\n",
		u.Scheme(), u.HostInfo().HostWithPort(), u.PathWithQueryFragment(), h.Get("User-Agent"))
	return &plugin.HijackedRequest{
		SuperProxy:     postmanEchoProxy(info),
		OverrideHeader: bytes.Replace(h.RawHeader(), []byte("-via-proxy"), []byte(""), -1),
	}, nil
}

func hijackPostmanEchoSSLFunc(info *plugin.RequestConnInfo) *plugin.HijackedRequest {
	return &plugin.HijackedRequest{
		SuperProxy: postmanEchoProxy(info),
	}
}

func postmanEchoProxy(info *plugin.RequestConnInfo) *superproxy.SuperProxy {
	if info == nil {
		return nil
	}
	if info.Context == nil {
		return nil
	}
	v := info.Context.Value("proxy")
	if enableProxy, ok := v.(bool); ok {
		if enableProxy {
			p, _ := superproxy.NewSuperProxy("127.0.0.1", 1080, superproxy.ProxyTypeSOCKS5,
				"", "", "")
			return p
		}
	}
	return nil
}

type respStdoutWriter struct {
}

func (w *respStdoutWriter) Close() error { return nil }

func (w *respStdoutWriter) WriteHeader(statusLine http.ResponseLine, header http.Header, rawHeader []byte) error {
	os.Stdout.WriteString(strconv.Quote(string(statusLine.GetResponseLine())+string(rawHeader)) + "\n")
	return nil
}

func (w *respStdoutWriter) Write(p []byte) (n int, err error) {
	return os.Stdout.Write(p)
}
