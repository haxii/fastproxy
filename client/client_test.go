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
	s := "GET / HTTP/1.1\r\n" +
		"\r\n"
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
