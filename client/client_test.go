package client

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	proxyhttp "github.com/haxii/fastproxy/proxy/http"
)

/*
func TestClientDo(t *testing.T) {
	ln, err := net.Listen("tcp", "0.0.0.0:5050")
	if err != nil {
		t.Fatalf("unexpect error: %s", err)
	}
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}

	uri := "/foo/bar/baz?a=b&cd=12"
	body := "request body"

	ch := make(chan error)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			ch <- fmt.Errorf("cannot accept client connection: %s", err)
			return
		}
		br := bufio.NewReader(conn)

		var req proxyhttp.Request
		if err = req.ReadFrom(br); err != nil {
			ch <- fmt.Errorf("cannot read client request: %s", err)
			return
		}
		if string(req.Method()) != "POST" {
			ch <- fmt.Errorf("unexpected request method: %q. Expecting %q", req.Method(), "POST")
			return
		}
		reqURI := req.PathWithQueryFragment()
		if string(reqURI) != uri {
			ch <- fmt.Errorf("unexpected request uri: %q. Expecting %q", reqURI, uri)
			return
		}
		contentLength := req.GetSize()
		if contentLength != len(body) {
			ch <- fmt.Errorf("unexpected content-length %d. Expecting %d", contentLength, len(body))
			return
		}
		//TODO: body test

		var resp proxyhttp.Response
		bw := bufio.NewWriter(conn)
		if err = resp.WriteTo(bw); err != nil {
			ch <- fmt.Errorf("cannot send response: %s", err)
			return
		}
		if err = bw.Flush(); err != nil {
			ch <- fmt.Errorf("cannot flush response: %s", err)
			return
		}
		ch <- nil
	}()

	conn, err := net.Dial("tcp", "127.0.0.1:5050")
	if err != nil {
		t.Fatalf("error when connect: %s", err)
	}
	bufioReader := bufio.NewReader(conn)
	req := &proxyhttp.Request{}
	resp := &proxyhttp.Response{}
	err = req.ReadFrom(bufioReader)
	if err != nil {
		t.Fatalf("error when readFrom request: %s", err)
	}
	err = c.Do(req, resp)
	if err != nil {
		t.Fatalf("error when doing request: %s", err)
	}
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout")
	}
}*/

func TestClientDo(t *testing.T) {
	var err error
	bPool := bufiopool.New(bufiopool.MinReadBufferSize, bufiopool.MinWriteBufferSize)
	c := &Client{
		BufioPool: bPool,
	}
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Hello world,tteterete%s!\r\n", r.URL.Path[1:])
		})
		log.Fatal(http.ListenAndServe(":10000", nil))
	}()
	s := `GET / HTTP/1.1
	Content-Length: 521
	Content-Type: multipart/form-data
	`
	req := &proxyhttp.Request{}
	br := bufio.NewReader(strings.NewReader(s))
	err = req.ReadFrom(br)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	req.SetHostWithPort("localhost:10000")
	resp := &proxyhttp.Response{}
	for i := 0; i < 10; i++ {
		err = c.Do(req, resp)
		if err != nil {
			t.Fatalf("unexpected error on iteration %d: %s", i, err)
		}

		// sleep for a while, so the connection to the host may expire.
		if i%5 == 0 {
			time.Sleep(30 * time.Millisecond)
		}
	}
}
