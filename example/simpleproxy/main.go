package main

import (
	"net"

	"github.com/haxii/fastproxy/proxy"
)

func main() {
	ln, err := net.Listen("tcp4", "0.0.0.0:8080")
	if err != nil {
		return
	}
	proxy.NewSimpleProxy().Serve(ln)
}
