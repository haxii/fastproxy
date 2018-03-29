package transport

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/haxii/fastproxy/cert"
)

func TestTransportForwordAndDial(t *testing.T) {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			fmt.Fprint(w, "GET /hello HTTP/1.1\r\nHOST: 127.0.0.1:9999\r\n\r\n")
		})
		http.ListenAndServe(":9990", nil)
	}()
	go func() {
		http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
			fmt.Fprint(w, "Hello World")
		})
		http.ListenAndServe(":9999", nil)
	}()
	connDst, err := Dial("127.0.0.1:9999")
	if err != nil {
		t.Fatal("dial dst error")
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://localhost:9990", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	_, err = Forward(connDst, resp.Body, 1*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	result := make([]byte, 1000)
	_, err = connDst.Read(result)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(result), "Hello World") {
		t.Fatal("transport error")
	}
	defer connDst.Close()
}

func TestTransportDialTLS(t *testing.T) {
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
	f, err := os.Create(".server.crt")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	f.Write([]byte(serverCrt))
	f.Close()

	defer os.Remove(".server.crt")
	cfg := cert.MakeClientTLSConfigByCA("", "", ".server.crt")
	conn, err := DialTLS("127.0.0.1:444", cfg)
	if err != nil {
		t.Fatalf("Dial error: %s", err.Error())
	}
	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1:444\r\n\r\n"))
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	result := make([]byte, 1000)
	_, err = conn.Read(result)
	if err != nil {
		t.Fatalf("unexpected error: %s", err.Error())
	}
	if !strings.Contains(string(result), "HTTP/1.1 200") {
		t.Fatal("DialTLS doesn't work")
	}
}
