package main

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/balinor2017/fastproxy/bufiopool"
	"github.com/balinor2017/fastproxy/client"
	"github.com/balinor2017/fastproxy/superproxy"
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

func (r *simpleReq) WriteHeaderTo(w *bufio.Writer) (int, int, error) {
	header := "Host: localhost\r\nUser-Agent: test client\r\n\r\n"
	n, err := w.WriteString(header)
	if err != nil {
		return len(header), n, err
	}
	err = w.Flush()
	return len(header), n, err
}

func (r *simpleReq) WriteBodyTo(w *bufio.Writer) (int, error) {
	return 0, nil
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

type simpleResp struct{}

func (r *simpleResp) ReadFrom(discardBody bool, br *bufio.Reader) (int, error) {
	fmt.Println("should discard body a.k.a this is a head response:", discardBody)
	b, err := br.ReadBytes('!')
	if err != nil {
		fmt.Println("error occurred when reading response", err)
	}
	fmt.Printf("full response: \n%s", b)
	return len(b), nil
}

func (r *simpleResp) ConnectionClose() bool {
	return false
}

type simpleReadWriter struct {
	readNum int
}

var reqRawbytes = []byte("GET / HTTP/1.1\r\nHost: 0.0.0.0:8090\r\n\r\n")

func (rw *simpleReadWriter) Read(p []byte) (n int, err error) {
	numOfBytesToWrite := len(reqRawbytes) - rw.readNum

	if numOfBytesToWrite > 0 {
		if numOfBytesToWrite > len(p) {
			numOfBytesToWrite = len(p)
		}
		copy(p[:numOfBytesToWrite], reqRawbytes[rw.readNum:rw.readNum+numOfBytesToWrite])
		rw.readNum += numOfBytesToWrite
	} else {
		// stuck here for further read
		time.Sleep(time.Hour)
	}

	return numOfBytesToWrite, nil
}

func (rw *simpleReadWriter) Write(p []byte) (n int, err error) {
	fmt.Printf("%s", p)
	if len(p) == 0 {
		// stuck here for further write
		time.Sleep(time.Hour)
	}
	return len(p), nil
}

func main() {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello world!")
		})
		http.ListenAndServe("0.0.0.0:8090", nil)
	}()

	// Do
	time.Sleep(time.Second)
	fmt.Println()
	client := &client.Client{BufioPool: bufiopool.New(1, 1)}
	fmt.Println(client.Do(&simpleReq{}, &simpleResp{}))

	// Do Fake
	time.Sleep(time.Second)
	fmt.Println()
	fmt.Println(client.DoFake(&simpleReq{}, &simpleResp{}, strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello!")))

	// Do Raw
	time.Sleep(time.Second)
	fmt.Println()
	fmt.Println(client.DoRaw(&simpleReadWriter{}, nil, "0.0.0.0:8090", nil))

}
