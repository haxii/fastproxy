package superproxy

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/balinor2017/fastproxy/bufiopool"
)

func testInitHTTPCertAndAuth(t *testing.T, superProxy *SuperProxy, isSSL bool, host, user, pass, cert, expServerName string, expServerInsecureSkipVerify bool) {
	superProxy.initHTTPCertAndAuth(isSSL, host, user, pass, cert)
	if superProxy.tlsConfig.ServerName != expServerName {
		t.Fatalf("Expected server name is %s, but get an unexpected server name: %s", expServerName, superProxy.tlsConfig.ServerName)
	}
	if len(user) > 0 && len(pass) > 0 {
		if len(superProxy.authHeaderWithCRLF) == 0 {
			t.Fatal("Expected authHeaderWithCRLF is not empty, but is empty")
		}
	} else {
		if len(superProxy.authHeaderWithCRLF) > 0 {
			t.Fatalf("Expected authHeaderWithCRLF is empty, but get %s", superProxy.authHeaderWithCRLF)
		}
	}
	if isSSL && superProxy.tlsConfig.InsecureSkipVerify != expServerInsecureSkipVerify {
		t.Fatalf("Expected server insecureSkipVerify error")
	}
}

func TestInitHTTPCertAndAuth(t *testing.T) {
	superProxy, err := NewSuperProxy("localhost", uint16(3128), ProxyTypeHTTP, "", "", "")
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
	testInitHTTPCertAndAuth(t, superProxy, true, "server", "", "", "", "server", false)
	testInitHTTPCertAndAuth(t, superProxy, true, "", "", "", "", "", true)
	testInitHTTPCertAndAuth(t, superProxy, true, "", "", "", serverCrt, "", true)
	testInitHTTPCertAndAuth(t, superProxy, false, "localhost", "", "", "", "", false)
	testInitHTTPCertAndAuth(t, superProxy, false, "localhost", "user", "pwd", "", "", false)
	testInitHTTPCertAndAuth(t, superProxy, false, "", "user", "", "", "", false)
	testInitHTTPCertAndAuth(t, superProxy, true, "server", "", "", serverCrt, "server", false)
}

func TestWriteHTTPProxyReqAndReadHTTPProxyResp(t *testing.T) {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello world!"))
		})
		http.ListenAndServe(":8999", nil)
	}()
	time.Sleep(1 * time.Second)
	superProxy, _ := NewSuperProxy("localhost", uint16(3128), ProxyTypeHTTP, "", "", "")
	conn, err := net.Dial("tcp", "localhost:3128")
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
	if !bytes.Contains(b, []byte("200 Connection established")) {
		t.Fatalf("unexpected status line: %s, expected: HTTP/1.1 200 OK", string(b))
	}
	err = conn.Close()
	if err != nil {
		t.Fatalf("connection close error: %s", err)
	}

	conn, err = net.Dial("tcp", "localhost:3128")
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

	conn, err = net.Dial("tcp", "localhost:3128")
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
	if !strings.Contains(err.Error(), "connected to proxy failed with start line") {
		t.Fatalf("expected error: connected to proxy failed with start line HTTP/1.1 502 Bad Gateway, but unexpected error: %s", err)
	}
	err = conn.Close()
	if err != nil {
		t.Fatalf("connection close error: %s", err)
	}
}
