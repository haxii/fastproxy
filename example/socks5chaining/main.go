package main

import (
	"github.com/haxii/fastproxy/proxy"
	"github.com/haxii/fastproxy/superproxy"
)

func main() {
	superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 8080,
		superproxy.ProxyTypeHTTP, "", "", "")
	p := proxy.Proxy{
		SuperProxy: superProxy,
	}
	panic(p.Serve("tcp", "0.0.0.0:8081"))
}
