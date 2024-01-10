package server

import (
	"io/ioutil"
	"net"
	"testing"
	"time"
)

func TestWorkerPoolStartStop(t *testing.T) {
	wp := &WorkerPool{
		WorkerFunc:      func(conn net.Conn) error { return nil },
		MaxWorkersCount: 10,
	}
	for i := 0; i < 10; i++ {
		wp.Start()
		wp.Stop()
	}
}

func TestWorkerPoolMaxWorkersCountSerial(t *testing.T) {
	testWorkerPoolMaxWorkersCountMulti(t)
}

func testWorkerPoolMaxWorkersCountMulti(t *testing.T) {
	for i := 0; i < 5; i++ {
		testWorkerPoolMaxWorkersCount(t)
	}
}

func testWorkerPoolMaxWorkersCount(t *testing.T) {
	ready := make(chan struct{})
	wp := WorkerPool{
		WorkerFunc: func(conn net.Conn) error {
			buf := make([]byte, 100)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			buf = buf[:n]
			if string(buf) != "foobar" {
				t.Fatalf("unexpected data read: %q. Expecting %q", buf, "foobar")
			}
			if _, err = conn.Write([]byte("baz")); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			<-ready

			return nil
		},
		MaxWorkersCount: 10,
	}
	wp.Start()

	ln, err := net.Listen("tcp", "0.0.0.0:5055")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	clientCh := make(chan struct{}, wp.MaxWorkersCount)
	for i := 0; i < wp.MaxWorkersCount; i++ {
		go func() {
			conn, err := net.Dial("tcp", "127.0.0.1:5055")
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if _, err := conn.Write([]byte("foobar")); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			data, err := ioutil.ReadAll(conn)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if string(data) != "baz" {
				t.Fatalf("unexpected value read: %q. Expecting %q", data, "baz")
			}
			if err = conn.Close(); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			clientCh <- struct{}{}
		}()
	}

	for i := 0; i < wp.MaxWorkersCount; i++ {
		conn, err := ln.Accept()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if !wp.Serve(conn) {
			t.Fatalf("worker pool must have enough workers to serve the conn")
		}
	}

	go func() {
		if _, err := net.Dial("tcp", "127.0.0.1:5055"); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	for i := 0; i < 5; i++ {
		if wp.Serve(conn) {
			t.Fatalf("worker pool must be full")
		}
	}

	if err = conn.Close(); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	close(ready)

	for i := 0; i < wp.MaxWorkersCount; i++ {
		select {
		case <-clientCh:
		case <-time.After(time.Second):
			t.Fatalf("timeout")
		}
	}

	if err := ln.Close(); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	wp.Stop()
}
