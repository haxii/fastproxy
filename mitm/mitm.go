package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/balinor2017/fastproxy/util"
)

var (
	errWrongDomain = errors.New("wrong domain")
)

// HijackTLSConnection hijacks the given TLS connection by setting up a fake TLS server using MITM
// then return the fake server connection and the targetServerName ( a.k.a. server name declared in TLS
// handshake if the clients support SNI see http://tools.ietf.org/html/rfc4366#section-3.1 )
// onHandshake is called before the fake server handshaking is made with the connection
func HijackTLSConnection(certAuthority *tls.Certificate, c net.Conn, domainName string,
	onHandshake func(error) error) (serverConn *tls.Conn, targetServerName string, err error) {
	targetServerName = domainName
	if len(domainName) == 0 || strings.Contains(domainName, ":") {
		err = onHandshake(errWrongDomain)
		return
	}
	// make a cert for the provided domain
	var fakeTargetServerCert *tls.Certificate
	fakeTargetServerCert, err = SignLeafCertUsingCertAuthority(certAuthority, []string{domainName})
	if err != nil {
		err = onHandshake(err)
		return
	}
	fakeTargetServerTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*fakeTargetServerCert},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if len(hello.ServerName) > 0 {
				targetServerName = hello.ServerName
			}
			return SignLeafCertUsingCertAuthority(certAuthority, []string{targetServerName})
		},
	}
	// perform the fake handshake with the connection given
	serverConn = tls.Server(c, fakeTargetServerTLSConfig)
	if onHandshake != nil {
		if err = onHandshake(nil); err != nil {
			return
		}
	}
	if err = serverConn.Handshake(); err != nil {
		serverConn.Close()
		serverConn = nil
	}
	return
}

var (
	defaultMITMCertAuthority    *tls.Certificate
	defaultMITMCertAuthorityPEM = []byte(`
-----BEGIN CERTIFICATE-----
MIIB1jCCATigAwIBAgIBATAKBggqhkjOPQQDBDAdMRswGQYDVQQDExJHZW9UcnVz
dCBHbG9iYWwgQ0EwHhcNMTcwOTAyMTUyNzE0WhcNMjIwOTAxMTUyNzE0WjAdMRsw
GQYDVQQDExJHZW9UcnVzdCBHbG9iYWwgQ0EwgZswEAYHKoZIzj0CAQYFK4EEACMD
gYYABAGVr9JHBx3sGRZ62wb4vjsjgf0e9AQqhNxO7m7uASsHPoiXsfdV0GD/gXKf
rsNgtvm8FBQMAtuVsgTgfqJPji2jwgC7xTpZB8BFflW4t6G86ifD87fXLNzcuFgo
v5N8pomYMSyraVEWvZZ6Hl2VjL32ZkH/iDQpZKacJLwaaYpYMX39UKMmMCQwDgYD
VR0PAQH/BAQDAgH+MBIGA1UdEwEB/wQIMAYBAf8CAQIwCgYIKoZIzj0EAwQDgYsA
MIGHAkIA1ib8nXsLetEfjXvDY71nBGF6my6Nk+aMp/vNi5MbYIaz+TPWKHUq4+zo
49pxtUwEwWKKMpU2GYvJUgaz35SzD0oCQVrs1niHmySDjCnrUHJOawo+s2zL6svd
FJ6RtJFfkqJ7nh/8/djL0gBbmcCzPnma0ermJxHABxWnIVYPCYuN8GJR
-----END CERTIFICATE-----
`)
	defaultMITMCertAuthorityKeyPEM = []byte(`
-----BEGIN ECDSA PRIVATE KEY-----
MIHcAgEBBEIA1FCmb8JkZ8UBiLyZ3zaLE5ibDC+Y3BarrjssCkzPK7mtEOpbctqh
d0QGEvlOkv8bzp2J+Iw4iZBmCX81YtQyfCGgBwYFK4EEACOhgYkDgYYABAGVr9JH
Bx3sGRZ62wb4vjsjgf0e9AQqhNxO7m7uASsHPoiXsfdV0GD/gXKfrsNgtvm8FBQM
AtuVsgTgfqJPji2jwgC7xTpZB8BFflW4t6G86ifD87fXLNzcuFgov5N8pomYMSyr
aVEWvZZ6Hl2VjL32ZkH/iDQpZKacJLwaaYpYMX39UA==
-----END ECDSA PRIVATE KEY-----
`)
)

// DefaultMITMCertAuthorityPEM returns the default MITM Certificate authority embedded in code
func DefaultMITMCertAuthorityPEM() []byte {
	return defaultMITMCertAuthorityPEM
}

func init() {
	if cer, err := tls.X509KeyPair(defaultMITMCertAuthorityPEM,
		defaultMITMCertAuthorityKeyPEM); err == nil {
		defaultMITMCertAuthority = &cer
		if defaultMITMCertAuthority.Leaf, err = x509.
			ParseCertificate(defaultMITMCertAuthority.Certificate[0]); err != nil {
			log.Fatal("unable to make default CA leaf for TLS MITM", err)
		}
	} else {
		log.Fatal("unable to load default CA leaf for TLS MITM", err)
	}
}

func genECDSAKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

const (
	defaultMITMCertAuthorityName   = "GeoTrust Global CA"
	defaultMITMCertAuthorityMaxAge = 5 * 365 * 24 * time.Hour
	_MITMMITMCertAuthorityUsage    = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment | x509.KeyUsageCRLSign | x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
)

// MakeMITMCertAuthority generates a root certificate authority with private key for HTTPS MITM
// name is the common name for the certificate issuer, and cert valid time, default authority
// name and max age is used when no nil parameters provided
func MakeMITMCertAuthority(name string, certMaxAge time.Duration) (certPEM, keyPEM []byte, err error) {
	if certMaxAge <= 0 {
		certMaxAge = defaultMITMCertAuthorityMaxAge
	}
	if len(name) == 0 {
		name = defaultMITMCertAuthorityName
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(certMaxAge),
		KeyUsage:              _MITMMITMCertAuthorityUsage,
		IsCA:                  true,
		MaxPathLen:            2,
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
		BasicConstraintsValid: true,
	}
	key, err := genECDSAKeyPair()
	if err != nil {
		return
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: keyDER})
	return
}

const (
	leafCertMaxAge = 24 * time.Hour
	leafCertUsage  = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment | x509.KeyUsageCRLSign | x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
)

// SignLeafCertUsingCertAuthority signs a leaf certificate for domainNames using provided
// certificate authority default MITM certificate is used when no cert authority provided
func SignLeafCertUsingCertAuthority(certAuthority *tls.Certificate,
	domainNames []string) (*tls.Certificate, error) {
	if certAuthority == nil {
		certAuthority = defaultMITMCertAuthority
	}
	now := time.Now().Add(-1 * time.Hour).UTC()
	if !certAuthority.Leaf.IsCA {
		return nil, errors.New("invalid certificate authority provided: not a CA")
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, util.ErrWrapper(err, "failed to generate serial number")
	}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: domainNames[0]},
		NotBefore:             now,
		NotAfter:              now.Add(leafCertMaxAge),
		KeyUsage:              leafCertUsage,
		BasicConstraintsValid: true,
		DNSNames:              domainNames,
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
	}
	key, err := genECDSAKeyPair()
	if err != nil {
		return nil, err
	}
	x, err := x509.CreateCertificate(rand.Reader, template,
		certAuthority.Leaf, key.Public(), certAuthority.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.PrivateKey = key
	cert.Leaf, _ = x509.ParseCertificate(x)
	return cert, nil
}
