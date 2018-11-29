package main

import (
	"github.com/haxii/fastproxy/proxy"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/haxii/log"
)

func main() {
	superProxy, _ := superproxy.NewSuperProxy("127.0.0.1", 9099, superproxy.ProxyTypeSOCKS5, "", "", "")
	proxy := proxy.Proxy{
		Logger: &log.DefaultLogger{},
		Handler: proxy.Handler{
			URLProxy: func(userdata *proxy.UserData, hostWithPort string, uri []byte) *superproxy.SuperProxy {
				return superProxy
			},
		},
	}
	panic(proxy.Serve("tcp", "0.0.0.0:8080"))
}
