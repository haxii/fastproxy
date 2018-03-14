package main

import (
	"bufio"
	"fmt"
	"net/http"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/client"
	"github.com/haxii/fastproxy/superproxy"
)

type simpleReq struct{}

func (r *simpleReq) Method() []byte {
	return []byte("GET")
}
func (r *simpleReq) TargetWithPort() string {
	return "0.0.0.0:8090"
}

func (r *simpleReq) PathWithQueryFragment() []byte {
	return []byte("/")
}

func (r *simpleReq) Protocol() []byte {
	return []byte("HTTP/1.1")
}

func (r *simpleReq) WriteHeaderTo(w *bufio.Writer) error {
	w.WriteString("Host: www.bing.com\r\nUser-Agent: test client\r\n\r\n")
	return w.Flush()
}

func (r *simpleReq) WriteBodyTo(w *bufio.Writer) error {
	return nil
}
func (r *simpleReq) ConnectionClose() bool {
	return false
}

func (r *simpleReq) IsTLS() bool {
	return false
}
func (r *simpleReq) TLSServerName() string {
	return ""
}

func (r *simpleReq) GetProxy() *superproxy.SuperProxy {
	return nil
}

func (r *simpleReq) GetReadSize() int {
	return 0
}

func (r *simpleReq) GetWriteSize() int {
	return 0
}

func (r *simpleReq) AddReadSize(n int) {}

func (r *simpleReq) AddWriteSize(n int) {}

type simpleResp struct{}

func (r *simpleResp) ReadFrom(discardBody bool, br *bufio.Reader) error {
	fmt.Println("should discard body a.k.a this is a head response:", discardBody)
	b, err := br.ReadBytes('!')
	if err != nil {
		fmt.Println("error occurred when reading response", err)
	}
	fmt.Printf("full response: \n%s", b)
	return nil
}

func (r *simpleResp) ConnectionClose() bool {
	return false
}

func (r *simpleResp) GetSize() int {
	return 0
}

func main() {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello world!")
		})
		http.ListenAndServe("0.0.0.0:8090", nil)
	}()
	time.Sleep(time.Second)
	client := &client.Client{BufioPool: bufiopool.New(1, 1)}
	if err := client.Do(&simpleReq{}, &simpleResp{}); err != nil {
		fmt.Println("error occurred when making client request: \n", err)
	}
}
