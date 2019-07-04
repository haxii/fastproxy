package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/haxii/fastproxy/uri"

	"github.com/haxii/fastproxy/plugin"
	"github.com/haxii/fastproxy/proxy"
	"github.com/haxii/log"
)

func main() {
	hijackHandler := plugin.HijackHandler{
		RewriteHost: func(host, port string) (newHost, newPort string) {
			fmt.Printf("RewriteHost handler called %s:%s\n", host, port)
			return host, port
		},
		SSLBump: func(host string) bool {
			fmt.Println("SSLBump handler called: ", host)
			return true
		},
		RewriteTLSServerName: func(serverName string) string {
			fmt.Println("RewriteTLSServerName handler called: ", serverName)
			return serverName
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

	p := proxy.Proxy{
		Logger:             &log.DefaultLogger{},
		ServerIdleDuration: time.Second * 30,
		HijackerPool:       &plugin.HijackerPool{Handler: hijackHandler},
	}
	panic(p.Serve("tcp", "0.0.0.0:8082"))
}

func printResponseFunc(u *uri.URI, h *plugin.RequestHeader) (*plugin.HijackedRequest, *plugin.HijackedResponse) {
	fmt.Printf("printResponseFunc called, with Scheme %s Host %s, URL %s, User-Agent %s\n\n",
		u.Scheme(), u.HostInfo().HostWithPort(), u.PathWithQueryFragment(), h.Get("User-Agent"))
	return nil, &plugin.HijackedResponse{ResponseType: plugin.HijackedResponseTypeInspect, InspectWriter: os.Stdout}
}

func hijackEvilFunc(u *uri.URI, h *plugin.RequestHeader) (*plugin.HijackedRequest, *plugin.HijackedResponse) {
	fmt.Printf("hijackEvilFunc called, with Scheme %s Host %s, URL %s, User-Agent %s\n\n",
		u.Scheme(), u.HostInfo().HostWithPort(), u.PathWithQueryFragment(), h.Get("User-Agent"))
	return nil, &plugin.HijackedResponse{
		ResponseType: plugin.HijackedResponseTypeOverride,
		OverrideReader: strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 56\r\nConnection: close\r\n\r\n" +
			"You're blocked from visiting evil sites via this proxy.\n"),
	}
}

func blockRequestFunc(u *uri.URI, h *plugin.RequestHeader) (*plugin.HijackedRequest, *plugin.HijackedResponse) {
	fmt.Printf("blockRequestFunc called, with Scheme %s Host %s, URL %s, User-Agent %s\n\n",
		u.Scheme(), u.HostInfo().HostWithPort(), u.PathWithQueryFragment(), h.Get("User-Agent"))
	return nil, &plugin.HijackedResponse{ResponseType: plugin.HijackedResponseTypeBlock}
}
