package hijack

import (
	"bufio"
	"io"

	"github.com/haxii/fastproxy/bufiopool"
)

//Request hijacked http request
type Request interface {
	// WriteHeaderTo read header from request, then Write To buffer IO writer
	// hijacked client.Request, target buffer IO writer acts like /dev/null
	WriteHeaderTo(*bufio.Writer) (readNum int, writeNum int, err error)

	// WriteBodyTo read body from request, then Write To buffer IO writer
	// hijacked client.Request, target buffer IO writer acts like /dev/null
	WriteBodyTo(*bufio.Writer) (int, error)
}

//Response hijacked http response
type Response interface {
	// ReadFrom read the http response from the buffer IO reader
	// hijacked client.Response, target buffer IO reader reads response
	// from suppiled reader directly
	ReadFrom(discardBody bool, br *bufio.Reader) (int, error)
}

//Client fill the target response using hijacked response reader
type Client struct {
	bufioPool bufiopool.Pool
}

//Do make the hijack response using
func (c *Client) Do(req Request, resp Response, hijackedRespReader io.Reader) (reqReadNum int,
	reqWriteNum int, responseNum int, err error) {
	if reqReadNum, reqWriteNum, err = c.writeReqToDevNull(req); err != nil {
		return reqReadNum, reqWriteNum, responseNum, err
	}
	bufHijackedRespReader := c.bufioPool.AcquireReader(hijackedRespReader)
	defer c.bufioPool.ReleaseReader(bufHijackedRespReader)
	responseNum, err = resp.ReadFrom(false, bufHijackedRespReader)
	return reqReadNum, reqWriteNum, responseNum, err
}

func (c *Client) writeReqToDevNull(req Request) (readNum int, writeNum int, err error) {
	devNullBufferedWriter := c.bufioPool.AcquireWriter(defaultDevNullWriter)
	defer c.bufioPool.ReleaseWriter(devNullBufferedWriter)
	if readNum, writeNum, err = req.WriteHeaderTo(devNullBufferedWriter); err != nil {
		return readNum, writeNum, err
	}
	n, err := req.WriteBodyTo(devNullBufferedWriter)
	readNum += n
	writeNum += n
	return readNum, writeNum, err
}

// defaultDevNullWriter
// a simple implentation of /dev/null based on io.Writer
var defaultDevNullWriter = &devNullWriter{}

type devNullWriter struct{}

func (d *devNullWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}
