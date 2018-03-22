package main

import (
	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/proxy"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/log"
)

func main() {
	superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 9099, superproxy.ProxyTypeSOCKS5, "", "", "")
	proxy := proxy.Proxy{
		BufioPool:   &bufiopool.Pool{},
		Client:      client.Client{},
		ProxyLogger: &log.DefaultLogger{},
		Handler: proxy.Handler{
			URLProxy: func(hostInfo *proxy.HostInfo, uri []byte) *superproxy.SuperProxy {
				return superProxy
			},
		},
	}
	panic(proxy.Serve("0.0.0.0:8080"))
}
