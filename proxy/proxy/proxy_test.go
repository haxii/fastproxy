package proxy

import (
	"bufio"
	"fmt"
	"net"
	"testing"
)

func TestProxyServe(t *testing.T) {
	proxy := &Proxy{}
	ln, err := net.Listen("tcp", "0.0.0.0:5050")
	if err != nil {
		t.Fatalf("unexpect error: %s", err)
	}
	go func() {
		if err = proxy.Serve(ln); err != nil {
			t.Fatalf("unexpect error: %s", err)
		}
	}()

	conn, err := net.Dial("tcp", "0.0.0.0:5050")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	_, err = ln.Accept()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\n\r\n")
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if status != "400" {
		t.Fatalf("an error occurred when send get request")
	}
}
