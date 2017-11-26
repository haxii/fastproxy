package hijack

import (
	"bufio"

	"github.com/haxii/fastproxy/bufiopool"
)

//Request hijacked http request
type Request interface {
	// WriteHeaderTo read header from request, then Write To buffer IO writer
	// hijacked client.Request, target buffer IO writer acts like /dev/null
	WriteHeaderTo(*bufio.Writer) error

	// WriteBodyTo read body from request, then Write To buffer IO writer
	// hijacked client.Request, target buffer IO writer acts like /dev/null
	WriteBodyTo(*bufio.Writer) error
}

//Response hijacked http response
type Response interface {
	// ReadFrom read the http response from the buffer IO reader
	// hijacked client.Response, target buffer IO reader reads response
	// from suppiled reader directly
	ReadFrom(discardBody bool, br *bufio.Reader) error
}

//Client fill the target response using hijacked response reader
type Client struct {
	bufioPool bufiopool.Pool
}

//Do make the hijack response using
func (c *Client) Do(req Request, resp Response, hijackedRespReader *bufio.Reader) error {
	if err := c.writeReqToDevNull(req); err != nil {
		return err
	}

	return resp.ReadFrom(false, hijackedRespReader)
}

func (c *Client) writeReqToDevNull(req Request) error {
	devNullBufferedWriter := c.bufioPool.AcquireWriter(defaultDevNullWriter)
	c.bufioPool.ReleaseWriter(devNullBufferedWriter)
	if err := req.WriteHeaderTo(devNullBufferedWriter); err != nil {
		return err
	}
	return req.WriteBodyTo(devNullBufferedWriter)
}

// defaultDevNullWriter
// a simple implentation of /dev/null based on io.Writer
var defaultDevNullWriter = &devNullWriter{}

type devNullWriter struct{}

func (d *devNullWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}
