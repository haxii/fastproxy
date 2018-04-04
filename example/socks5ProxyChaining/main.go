package main

import (
	"github.com/balinor2017/fastproxy/proxy"
	"github.com/balinor2017/fastproxy/superproxy"
	"github.com/balinor2017/log"
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
