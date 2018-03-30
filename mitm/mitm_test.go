package mitm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"testing"
)

var (
	realServerAddr        = ":8000"
	realTLSServerListener net.Listener
	realServerConfig      *tls.Config
	realServerMessage     = []byte("hello world!")

	fakeServerAddr     = ":8001"
	fakeServerListener net.Listener
	fakeServerMessage  = []byte("hello MITM!")
)

func init() {
	// make real server certificate and config from cert and key PEM block
	var err error
	realServerConfig = &tls.Config{}
	realServerConfig.Certificates = make([]tls.Certificate, 1)
	realServerConfig.Certificates[0], err = tls.X509KeyPair(realServerCertPEM, realServerKeyPEM)
	if err != nil {
		log.Fatal(err)
	}
	realServerConfig.ServerName = "localhost"

	// make the real server tls listener
	var realServerListener net.Listener
	realServerListener, err = net.Listen("tcp", realServerAddr)
	if err != nil {
		log.Fatal(err)
	}
	realTLSServerListener = tls.NewListener(realServerListener, realServerConfig)

	fakeServerListener, err = net.Listen("tcp", fakeServerAddr)
	if err != nil {
		log.Fatal(err)
	}
}

func TestHijackTLSConnection(t *testing.T) {

	//TODO:
	t.Fatal("should test more cases")

	var failErr1, failErr2, failErr3, failErr4 error
	// start real server
	wg := sync.WaitGroup{}
	wg.Add(4)
	go func(failErr *error) {
		defer wg.Done()
		conn, err := realTLSServerListener.Accept()
		if err != nil {
			*failErr = err
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(realServerMessage)); err != nil {
			*failErr = err
			return
		}
	}(&failErr1)
	// start fake server
	go func(failErr *error) {
		defer wg.Done()
		conn, err := fakeServerListener.Accept()
		if err != nil {
			*failErr = err
			return
		}
		defer conn.Close()
		fakeConn, serverName, err := HijackTLSConnection(nil, conn, "localhost", nil)
		if err != nil {
			*failErr = err
			return
		}
		defer fakeConn.Close()
		if serverName != "another-localhost" {
			*failErr = fmt.Errorf("expect server name %s, got %s", "another-localhost", serverName)
			return
		}
		if _, err := fakeConn.Write([]byte(fakeServerMessage)); err != nil {
			*failErr = err
			return
		}
	}(&failErr2)

	go func(failErr *error) {
		// real server client
		defer wg.Done()
		realConn, err := net.Dial("tcp", realServerAddr)
		if err != nil {
			*failErr = err
			return
		}
		defer realConn.Close()
		realClientRootCA := x509.NewCertPool()
		realClientRootCA.AppendCertsFromPEM(realServerCertPEM)
		realClientConfig := &tls.Config{RootCAs: realClientRootCA, ServerName: "localhost"}
		realClientConn := tls.Client(realConn, realClientConfig)
		if err := realClientConn.Handshake(); err != nil {
			*failErr = err
			return
		}
		if msg, err := ioutil.ReadAll(realClientConn); err != nil {
			*failErr = err
			return
		} else if !bytes.Equal(realServerMessage, msg) {
			*failErr = fmt.Errorf("expected %s, got %s", realServerMessage, msg)
			return
		}
	}(&failErr3)

	go func(failErr *error) {
		// fake server client
		defer wg.Done()
		fakeConn, err := net.Dial("tcp", fakeServerAddr)
		if err != nil {
			*failErr = err
			return
		}
		defer fakeConn.Close()
		fakeClientRootCA := x509.NewCertPool()
		fakeClientRootCA.AppendCertsFromPEM(defaultMITMCertAuthorityPEM)
		fakeClientConfig := &tls.Config{
			RootCAs:    fakeClientRootCA,
			ServerName: "another-localhost",
		}
		fakeClientConn := tls.Client(fakeConn, fakeClientConfig)
		if err := fakeClientConn.Handshake(); err != nil {
			*failErr = err
			return
		}
		if msg, err := ioutil.ReadAll(fakeClientConn); err != nil {
			*failErr = err
			return
		} else if !bytes.Equal(fakeServerMessage, msg) {
			*failErr = fmt.Errorf("expected %s, got %s", fakeServerMessage, msg)
			return
		}
	}(&failErr4)
	wg.Wait()
	if failErr1 != nil {
		t.Fatal(failErr1)
	}
	if failErr2 != nil {
		t.Fatal(failErr2)
	}
	if failErr3 != nil {
		t.Fatal(failErr3)
	}
	if failErr4 != nil {
		t.Fatal(failErr4)
	}
}

// spellcheck-off
var (
	realServerCertPEM = []byte(`
-----BEGIN CERTIFICATE-----
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
`)
	realServerKeyPEM = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCpavxAydg6qDcSHhzwcebD5v/o2yItY1a6cA8t4cd+8661TAQr
//YRISpIwUZ7TOLVdmnMuyUzxGABZQ5iwiKDqbl5GLxB/f3NRWv5Cr8vT4izFNP0
toIky5oEkDq/xBZvVnshBO6fpx1vulnow+3Y3WeriwVXvuQAQw5N8qod/QIDAQAB
AoGAdoPnDxOkdfQzAjOanwGvIyA3qZeSIxo5E5dMpxYozsB9WUpiKL2YT4dZ4yeB
vMOecyGxBY1tivc3CgK9u4x/Q2RWQqG4n6d++RKKWEk5Znvi5H35gOcWbQgnOLfe
VJKonqZwhDxWBjlIdKHRdlMY2qXY0rftDthas2zfLIWmSmkCQQDSX5zFhN1U3dAo
cni5Qx3zBCGGw8aoFAH4bUPuvtb7LTnDb+xJDcxhC9pIy+5e3PcSa7cVN0DJpXEo
QPMHp8jHAkEAziluenyR98PoJ2W/D8Cphuc5FvsRXOkGrcLdj397BZzTQhTrEPEr
/qhn2uC4PqGBuS+GV1zgjTf4ocAz7TGHGwJBAKQ7pm0A07V8URQygZLIFepxMCdA
UadHr14dFyqca8K9RNoRV1qU3hhpI2kvY5FFWdFUrCJw9zA060kso043q2MCQQCN
bdDTiGeeoC+/70XeKZ5i5Ha+tCgaI+YoB/l0utCLbiVjPPRxn/E9dwwgFG9wz90t
TFQN1LJbTp1rYW599q8nAkBDbXVZIDjwuL0SyUgnGJUKMILk0aanNE2E885wyuZm
PAnrpRqdDz9eQITxrUgW8vJKxBH6hNNGcMz9VHUgnsSE
-----END RSA PRIVATE KEY-----
`)
)
