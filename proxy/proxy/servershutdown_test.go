package proxy

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServerShutDownByRightParameters(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:7777")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	gln := NewGracefulListener(ln, 3*time.Second)
	addr := gln.Addr()
	if addr.Network() != "tcp" {
		t.Fatalf("Addr network is not tcp4, current addr network is %s", addr.Network())
	}
	if addr.String() != "[::]:7777" {
		t.Fatalf("Addr network is not 0.0.0.0:7777, current addr string is %s", addr.String())
	}
	conn, err := net.Dial("tcp4", "0.0.0.0:7777")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	gConn, err := gln.Accept()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	_, err = conn.Write([]byte("Hello, world!"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	b := make([]byte, 20)
	_, err = gConn.Read(b)
	if !bytes.Contains(b, []byte("Hello, world!")) {
		t.Fatalf("unexpected data read: %s, expected data is 'Hello, world!' ", string(b))
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if err := gConn.Close(); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if err = gln.Close(); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if conn, err = gln.Accept(); err == nil {
		t.Fatalf("expected error: use of closed network connection, gln do not close")
	}
}

func TestServerShutDownByWrongParameters(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:7777")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	gln := NewGracefulListener(nil, 3*time.Second)
	if gln != nil {
		t.Fatalf("gln should be nil")
	}

	gln = NewGracefulListener(ln, 3*time.Second)
	_, err = net.Dial("tcp4", "0.0.0.0:7777")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	gConn, err := gln.Accept()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	err = gln.Close()
	if err == nil {
		t.Fatalf("expected error: cannot complete graceful shutdown")
	}
	if strings.Contains(err.Error(), "expected error: cannot complete graceful shutdown") {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	err = gConn.Close()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	err = gln.Close()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}
