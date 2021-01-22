package mitm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
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

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func TestMakeCert(t *testing.T) {
	cert, err := SignLeafCertUsingCertAuthority(defaultMITMCertAuthority, "*.example.com")
	if err != nil {
		t.Fatal(err)
	}

	derBytes:=cert.Certificate[0]
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	fmt.Println(out.String())
	out.Reset()
	pem.Encode(out, pemBlockForKey(cert.PrivateKey))
	fmt.Println(out.String())
}

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
	//t.Fatal("should test more cases")

	var failErr1, failErr2, failErr3, failErr4 error
	// start real server
	wg := sync.WaitGroup{}
	wg.Add(4)
	go func(failErr *error) {
		defer wg.Done()
		conn, err := realTLSServerListener.Accept()
		if err != nil {
			*failErr = err
			fmt.Println("1:", err)
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(realServerMessage)); err != nil {
			fmt.Println("2:", err)
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
MIIC+zCCAeOgAwIBAgIJAONhl6/8qFKhMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDAeFw0xODA0MjcxMDI3MTRaFw0yODA0MjQxMDI3MTRaMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAN1q/YQxBQuMZAaq1bYtELHYOJKhQ5bYCVXQZEdrhYQ8c2rd88vKMLJmmWUG
O1mXroFvATibBLcNe9/+R905M/jSdYcGg1iHUSBjm0Exejqg6NWq3SYn1sZoejer
fZalWXJKVe7RnAeacVJ4S5HXzTfzXyHrc4C8v5VUyrIh1+tsRT+pidghX4cbZFM3
MofxSSCMHCHWUq54kwOa63fJmh8QXiy4OQavloWJgfllnhReRa5JOc6/1paPY2iM
GwCKoyc93PK4Lx2m4fmoQBK0DvAoClPyS5ZU/MaizRO/aV0Yzn7pO4y8afpQQGe0
YRJz+pDmiGMwBHOHTXiOHtmE738CAwEAAaNQME4wHQYDVR0OBBYEFB1Z+4R6eWHb
w1/U4RzO+V7gdqr9MB8GA1UdIwQYMBaAFB1Z+4R6eWHbw1/U4RzO+V7gdqr9MAwG
A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFI5BOSxxUwNWEgWpoDRYgm4
heLpzLwLzjXk61/Ny33W6nLRz+etIFaQjAVVwwAmMLHZmHweBZ492YGajfbEeQMo
5y9JjyJk45YzSISeadj9KAoQJPO0Xvovwgmzjt8bHGBTkqQ/+V4xDtG4H7/hqPJN
AwG0RF+fu/HHAYIB+7t7yZq2iLZYSYPSdsHJt/v6vvOD95u819Z10Eunfu+iGvyL
1wYjM9njIQwcUCxcfFHKz+b0PCWkj3X9Sfgid3p5q2KheMSaGBc1uVDqJ13hn2wn
QuJQcJriSPQ+9nQZR+aOMIoXkRDHzdi15F01Nax6ox0pZkpK+goU5sgEzlgX6zk=
-----END CERTIFICATE-----
`)

	realServerKeyPEM = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3Wr9hDEFC4xkBqrVti0Qsdg4kqFDltgJVdBkR2uFhDxzat3z
y8owsmaZZQY7WZeugW8BOJsEtw173/5H3Tkz+NJ1hwaDWIdRIGObQTF6OqDo1ard
JifWxmh6N6t9lqVZckpV7tGcB5pxUnhLkdfNN/NfIetzgLy/lVTKsiHX62xFP6mJ
2CFfhxtkUzcyh/FJIIwcIdZSrniTA5rrd8maHxBeLLg5Bq+WhYmB+WWeFF5Frkk5
zr/Wlo9jaIwbAIqjJz3c8rgvHabh+ahAErQO8CgKU/JLllT8xqLNE79pXRjOfuk7
jLxp+lBAZ7RhEnP6kOaIYzAEc4dNeI4e2YTvfwIDAQABAoIBAGwnMqY7e4dkkAdh
svpFkP4N67RT6TvpUsYEALeSIamyDX6J4+gLXzYFP7BFFwBwQuEeY65OqkLv5y5G
ervokSZdRuMpn0bC8jGr9c4maNnyd0jHKTbWBubraad/sNzA76wP+2GoKVrdabUq
5V7b1nYZ/sIGzGh5yesbe9b/CQUI+SKcfiSRFeVzJN0m50wI7tXZ3sQovMnBGQIO
XPBiHcUTGykJ1FKOCRdnKhpohwPXtZdYUE/DnrzzoQ6Ax1zSokw+5xbAT/OYKsei
S8/viSEDt1b+qlUcC2RQ1g8ndIl5q6wcXCWtYXN4oCCvQK3zyShN5zuoscNlneAS
hpldXYECgYEA9iKw9dr38l8AzZ8Y8ftYMpbHuKGukFDTPwoGMO1ey5bcYaH/jrd3
HNOdP0WuT/rrg/7eNHo4dpxgU+b6JJR6aFMCF38bixgllMiAqDAEZMPnKgcRcumH
V+JFqZ/65WLdgVdwfyQFDeSKP5+FcoMxsDjV/yxLzdnj70cgZeXaMG8CgYEA5kqz
afrtx/NIiXVLq+jRTMyuLx65TA3id41nDs6fiasYUKMeysYyduaKhnCl7JjVrxuW
FFT6KOvdw1NdZDEwg0JDOtWYjn6L928K9+14qzlcm2Bf/POCgBIrN9xTBkoGKP5V
tQDnKCE1Y3RZBGXUrLTWWn/bTyqMfIETVcIFmfECgYEAg4vS6/MVZRHlSf/nwxxD
7PWs1D6FH1gzLpPa7zdN3J1KN1vvS4U+QcfPWMuS9+fxC2ChvYY8uxekW/MsaXR5
X1xN1+T1AYfsPfJS4JCZKImS+GFCsBmjXhLujFOWMhZ+r+vdkfXcRaqJQKuvFJ6N
ZdNae8Be2yvCqFVpOUx5Kj0CgYEAzFS5ji5D7maxFK3LX5PqqW7umgZzuMSVDSic
qWmx6m+x2lJxjs9+lTsG7DRlNGGDL6SVbCLd95MYKCf+tFhkyAHyLvC4NK6ZuAiB
veupZps1zPMdGA5j2wjD6gOGcw0ZHCRWnYxYjaWxfjYMibdklXy6uH+7cim5jvrj
0fKeD7ECgYBB4JNn/ENLUeZ5zCtcl8ZOIneWa8x4o1i/CNE+xvJAc/xe22SrYoty
hfTIIKV3oyU8bCr6Er07btpZTRAFCk9kd8zpS9r28/PhZl7SrFd8mDxKLmOMNUgr
WZoEro0kBysFz36m27Pa32CMlWZhkD8gdi7gC2bJA8fM1dTU9GUJiQ==
-----END RSA PRIVATE KEY-----
`)
)
