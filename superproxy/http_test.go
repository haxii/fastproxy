package superproxy

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/haxii/fastproxy/bufiopool"
)

func TestInitHTTPCertAndAuth(t *testing.T) {
	superProxy, err := NewSuperProxy("localhost", uint16(8081), ProxyTypeHTTP, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	serverCrt := `-----BEGIN CERTIFICATE-----
MIICnzCCAggCCQDbF8N9hzgLKTANBgkqhkiG9w0BAQUFADCBkzELMAkGA1UEBhMC
c2gxGjAYBgNVBAgMEXNoYW5naGFpIGluIENoaW5hMREwDwYDVQQHDAhzaGFuZ2hh
aTEOMAwGA1UECgwFaGF4aWkxEDAOBgNVBAsMB3NlY3Rpb24xEjAQBgNVBAMMCWxv
Y2FsaG9zdDEfMB0GCSqGSIb3DQEJARYQNDkzODg1NTk3QHFxLmNvbTAeFw0xODAz
MDEwMzU4NDRaFw0xODAzMzEwMzU4NDRaMIGTMQswCQYDVQQGEwJzaDEaMBgGA1UE
CAwRc2hhbmdoYWkgaW4gY2hpbmExETAPBgNVBAcMCHNoYW5naGFpMQ4wDAYDVQQK
DAVoYXhpaTEQMA4GA1UECwwHc2VjdGlvbjESMBAGA1UEAwwJbG9jYWxob3N0MR8w
HQYJKoZIhvcNAQkBFhA0OTM4ODU1OTdAcXEuY29tMIGfMA0GCSqGSIb3DQEBAQUA
A4GNADCBiQKBgQCpavxAydg6qDcSHhzwcebD5v/o2yItY1a6cA8t4cd+8661TAQr
//YRISpIwUZ7TOLVdmnMuyUzxGABZQ5iwiKDqbl5GLxB/f3NRWv5Cr8vT4izFNP0
toIky5oEkDq/xBZvVnshBO6fpx1vulnow+3Y3WeriwVXvuQAQw5N8qod/QIDAQAB
MA0GCSqGSIb3DQEBBQUAA4GBAG45K4B2N8lEeCimTyYuS9yGRQINMfdZksL2aDyq
OL95JiCMKM1iFulom/fth3oxi1w95VRFaM4tO8qIBtKuFyWs8x1MMpTJlEamHFTe
H1Id2JuKgDgi4AmxfKPjh+j+U6iNbMgjwo6scfaWcpteGK0FA5jn4cmMmlwhkjCA
L/ib
-----END CERTIFICATE-----
`
	f, err := os.Create(".test_server.crt")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	f.Write([]byte(serverCrt))
	f.Close()

	defer os.Remove(".test_server.crt")
	superProxy.initHTTPCertAndAuth(true, "server", "", "", "")
	if superProxy.tlsConfig.ServerName != "server" {
		t.Fatalf("unexpected server name: %s, expected server name: localhost", superProxy.tlsConfig.ServerName)
	}
	if superProxy.tlsConfig.InsecureSkipVerify {
		t.Fatal("Expected InsecureSkipVerify property is false, but is true")
	}
	if superProxy.authHeaderWithCRLF != nil {
		t.Fatalf("expected auth header with CRLF: nil, but unexpected: %s", string(superProxy.authHeaderWithCRLF))
	}
	superProxy.initHTTPCertAndAuth(true, "", "", "", "")
	if !superProxy.tlsConfig.InsecureSkipVerify {
		t.Fatal("Expected InsecureSkipVerify property is true, but is false")
	}
	if len(superProxy.tlsConfig.Certificates) != 0 {
		t.Fatal("Expected Certificates property is empty")
	}
	superProxy.initHTTPCertAndAuth(true, "", "", "", ".test_server.crt")
	if !superProxy.tlsConfig.InsecureSkipVerify {
		t.Fatal("Expected InsecureSkipVerify property is true, but is false")
	}
	if len(superProxy.tlsConfig.Certificates) == 0 {
		t.Fatal("Expected Certificates property is not empty")
	}
	if superProxy.authHeaderWithCRLF != nil {
		t.Fatalf("expected auth header with CRLF: nil, but unexpected: %s", string(superProxy.authHeaderWithCRLF))
	}
	superProxy.initHTTPCertAndAuth(false, "localhost", "", "", "")
	if len(superProxy.tlsConfig.ServerName) != 0 {
		t.Fatalf("Expected tlsConfig should be nil, but unexpected: %s", superProxy.tlsConfig.ServerName)
	}
	if superProxy.authHeaderWithCRLF != nil {
		t.Fatalf("Write empty user and password, expected authHeaderWithCRLF is nil, but unexpected: %s", superProxy.authHeaderWithCRLF)
	}
	superProxy.initHTTPCertAndAuth(false, "localhost", "user", "pwd", "")
	if len(superProxy.authHeaderWithCRLF) == 0 {
		t.Fatal("Expected authHeaderWithCRLF is not empty, but is empty")
	}
	if !strings.Contains(string(superProxy.authHeaderWithCRLF), "Proxy-Authorization:") {
		t.Fatalf("Expected authHeaderWithCRLF contains Proxy-Authorization:, but unexpected: %s", string(superProxy.authHeaderWithCRLF))
	}
	superProxy.initHTTPCertAndAuth(false, "", "user", "", "")
	if len(superProxy.authHeaderWithCRLF) != 0 {
		t.Fatalf("Expected authHeaderWithCRLF is empty, but is not empty, unexpected: %s", string(superProxy.authHeaderWithCRLF))
	}
}

func TestWriteHTTPProxyReqAndReadHTTPProxyResp(t *testing.T) {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello world!"))
		})
		http.ListenAndServe(":8999", nil)
	}()
	time.Sleep(1 * time.Second)
	superProxy, _ := NewSuperProxy("localhost", uint16(8081), ProxyTypeHTTP, "", "", "")
	conn, err := net.Dial("tcp", "localhost:8081")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if _, err = superProxy.writeHTTPProxyReq(conn, []byte("localhost:8999")); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	b := make([]byte, 200)

	_, err = conn.Read(b)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !bytes.Contains(b, []byte("200 OK")) {
		t.Fatalf("unexpected status line: %s, expected: HTTP/1.1 200 OK", string(b))
	}
	err = conn.Close()
	if err != nil {
		t.Fatalf("connection close error: %s", err)
	}

	conn, err = net.Dial("tcp", "localhost:8081")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if _, err = superProxy.writeHTTPProxyReq(conn, []byte("localhost:8999")); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	pool := bufiopool.New(1, 1)
	err = superProxy.readHTTPProxyResp(conn, pool)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	err = conn.Close()
	if err != nil {
		t.Fatalf("connection close error: %s", err)
	}

	conn, err = net.Dial("tcp", "localhost:8081")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if _, err = superProxy.writeHTTPProxyReq(conn, []byte("localhost:8998")); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	err = superProxy.readHTTPProxyResp(conn, pool)
	if err == nil {
		t.Fatalf("unexpected error: onnected to proxy failed ")
	}
	if !strings.Contains(err.Error(), "connected to proxy failed with startline") {
		t.Fatalf("expected error: connected to proxy failed with startline HTTP/1.1 502 Bad Gateway, but unexpected error: %s", err)
	}
	err = conn.Close()
	if err != nil {
		t.Fatalf("connection close error: %s", err)
	}
}
