package http

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestParseHeaderFields(t *testing.T) {
	//TODO: large header
	//TODO: more error return tests
	//t.Fatal("fix todo")
	header1 := "Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\n\r\n"
	testParseHeaderFields(t, -1, header1, len(header1), nil, false, false, 0, "")
	testParseHeaderFields(t, 10, header1, 0, bufio.ErrBufferFull, false, false, 0, "")
	header1_1 := "Host: www.google.com\nUser-Agent: curl/7.54.0\n\r\n"
	testParseHeaderFields(t, -1, header1_1, len(header1_1), nil, false, false, 0, "")
	header1_2 := "Host: www.google.com\nUser-Agent: curl/7.54.0\n\n"
	testParseHeaderFields(t, -1, header1_2, len(header1_2), nil, false, false, 0, "")
	header2 := "Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\n\r\nextra"
	testParseHeaderFields(t, -1, header2, len(header2)-len("extra"), nil, false, false, 0, "")
	header2_1 := "Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\n\r\n\r\n"
	testParseHeaderFields(t, -1, header2_1, len(header2_1)-len("\r\n"), nil, false, false, 0, "")
	header3 := "Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\nConnection: close\r\n\r\n"
	testParseHeaderFields(t, -1, header3, len(header3), nil, true, false, 0, "")
	header3_1 := "Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\nconnection: close\r\n\r\n"
	testParseHeaderFields(t, -1, header3_1, len(header3_1), nil, true, false, 0, "")
	header3_2 := "Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\nconnECtion: cLose\r\n\r\n"
	testParseHeaderFields(t, -1, header3_2, len(header3_2), nil, true, false, 0, "")
	header4 := "Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\nProxy-Connection: Keep-Alive\r\n\r\n"
	testParseHeaderFields(t, -1, header4, len(header4), nil, false, false, 0, "")
	header4_1 := "Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\nProxy-Connection: Close\r\n\r\n"
	testParseHeaderFields(t, -1, header4_1, len(header4_1), nil, false, true, 0, "")
	header4_2 := "Host: www.google.com\r\nUser-Agent: curl/7.54.0\r\nProxy-connection: clOse\r\n\r\n"
	testParseHeaderFields(t, -1, header4_2, len(header4_2), nil, false, true, 0, "")
	header5 := "Connection: keep-alive\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 10\r\n\r\n"
	testParseHeaderFields(t, -1, header5, len(header5), nil, false, false, 10, "")
	header6 := "Transfer-Encoding: chunked\r\nContent-Type: text/html; charset=ISO-8859-1\r\n\r\n"
	testParseHeaderFields(t, -1, header6, len(header6), nil, false, false, -1, "text/html; charset=ISO-8859-1")
	header7 := "Connection: Close\r\nServer: Microsoft-IIS/10.0\r\nTransfer-Encoding: identity\r\n\r\n"
	testParseHeaderFields(t, -1, header7, len(header7), nil, true, false, -2, "")
	header8 := "\n"
	testParseHeaderFields(t, -1, header8, len(header8), nil, false, false, 0, "")
	header8_1 := "\nextra"
	testParseHeaderFields(t, -1, header8_1, len(header8_1)-len("extra"), nil, false, false, 0, "")
	header9 := "\r\n"
	testParseHeaderFields(t, -1, header9, len(header9), nil, false, false, 0, "")
	header10 := "\n\r\n"
	testParseHeaderFields(t, -1, header10, len(header10)-len("\r\n"), nil, false, false, 0, "")
	header11 := "\r"
	testParseHeaderFields(t, -1, header11, 0, io.EOF, false, false, 0, "")
	header12 := "?!\r"
	testParseHeaderFields(t, -1, header12, 0, io.EOF, false, false, 0, "")
	header13 := "not even a header"
	testParseHeaderFields(t, -1, header13, 0, io.EOF, false, false, 0, "")
}

func testParseHeaderFields(t *testing.T, bufioBufferSize int, sampleHeader string, expectingHeaderLen int,
	expectingError error, expectingIsConnectionClose, expectingIsProxyConnectionClose bool,
	expectingContentLength int64, expectingContentType string) {
	reader := strings.NewReader(sampleHeader)
	var bufReader *bufio.Reader
	if bufioBufferSize <= 0 {
		bufReader = bufio.NewReaderSize(reader, 2*len(sampleHeader))
	} else {
		bufReader = bufio.NewReaderSize(reader, bufioBufferSize)
	}
	header := Header{}
	headerLen, err := header.ParseHeaderFields(bufReader)
	if headerLen != expectingHeaderLen {
		t.Errorf("unexpected header length %d, expecting %d", headerLen, expectingHeaderLen)
	}
	if err != expectingError {
		t.Errorf("unexpected error %s, expecting %s", err, expectingError)
	}
	if header.isConnectionClose != expectingIsConnectionClose {
		t.Errorf("unexpected connection close state %+v, expecting %+v",
			header.isConnectionClose, expectingIsConnectionClose)
	}
	if header.isProxyConnectionClose != expectingIsProxyConnectionClose {
		t.Errorf("unexpected proxy proxy connection close state %+v, expecting %+v",
			header.isProxyConnectionClose, expectingIsProxyConnectionClose)
	}
	if header.contentLength != expectingContentLength {
		t.Errorf("unexpected content length %d, expecting %d",
			header.contentLength, expectingContentLength)
	}
	if header.contentType != expectingContentType {
		t.Errorf("unexpected content type %s, expecting %s",
			header.contentType, expectingContentType)
	}
}
