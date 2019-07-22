package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/haxii/fastproxy/util"
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
	fakeTargetServerCert, err = SignLeafCertUsingCertAuthority(certAuthority, domainName)
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
			return SignLeafCertUsingCertAuthority(certAuthority, targetServerName)
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
MIIC2zCCAcOgAwIBAgIBATANBgkqhkiG9w0BAQ0FADAdMRswGQYDVQQDExJHZW9U
cnVzdCBHbG9iYWwgQ0EwHhcNMTkwNTI0MTIxOTU4WhcNMjQwNTIyMTIxOTU4WjAd
MRswGQYDVQQDExJHZW9UcnVzdCBHbG9iYWwgQ0EwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDFtEYsV81zI+uEvcfqyn43T2hwfiWqfCs/OKRqDUWXxSO4
0R5oZJOkxrZTCu8zDKlmqn+cLcWYR9bo19s18H93/C+Gk0cyntvcu7dqHCIr5R/a
lJTTBhQK1mPogE9rJ+OTSQ4IlKhI3Dm/SNlDHNW3+lqpiRIsAsMWVFIQ++HQewTY
cti+zgDtSjpxLuLhKS898mLx53lHFTeynMXajZ1EuemWkCYVOvCZcoFqT63+ZKcP
KvU+wmbaAjdJzQp/fn6GwR/SdpBnJ65MmYApOCJ1Rs7eRkyGmKObJ6k/UNuLuLwQ
98gpScOEiPq+FAJF6CHXgUzeZhJjj7lnxtoebl0lAgMBAAGjJjAkMA4GA1UdDwEB
/wQEAwIB/jASBgNVHRMBAf8ECDAGAQH/AgECMA0GCSqGSIb3DQEBDQUAA4IBAQDE
dEaNlX1p9gEk8CRAOf8qELC92VdzVQZvo8/z3n43+nGE1KpNtJA9w2f6igw3SGmA
gAm7ICyQBNfUCIchfVYQc6XwFAXTt4jJUZ8VS2pviAF+VCHHssyQnTnHXqgAZ8iD
P6HXMNHXE3wDXGemPDVicoZVFwVBFX4bkkQO6nq1dbLb1yqZ535R6mZ/IozpWPnb
hiZMf6htwEQWOPb8XL1kIdFHoar/kwvSA4pxdHs5ftrMkMkvKEYTHThX1tl7L98W
RC2VbQYlB/vS5+YjUcgLkBpbxTvVeYzZ0b72mxZrEMF6kEiEjLV+TD+MJdKuCRPp
6trox+/FtSz+wk2QOFZy
-----END CERTIFICATE-----
`)
	defaultMITMCertAuthorityKeyPEM = []byte(`
-----BEGIN ECDSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxbRGLFfNcyPrhL3H6sp+N09ocH4lqnwrPzikag1Fl8UjuNEe
aGSTpMa2UwrvMwypZqp/nC3FmEfW6NfbNfB/d/wvhpNHMp7b3Lu3ahwiK+Uf2pSU
0wYUCtZj6IBPayfjk0kOCJSoSNw5v0jZQxzVt/paqYkSLALDFlRSEPvh0HsE2HLY
vs4A7Uo6cS7i4SkvPfJi8ed5RxU3spzF2o2dRLnplpAmFTrwmXKBak+t/mSnDyr1
PsJm2gI3Sc0Kf35+hsEf0naQZyeuTJmAKTgidUbO3kZMhpijmyepP1Dbi7i8EPfI
KUnDhIj6vhQCRegh14FM3mYSY4+5Z8baHm5dJQIDAQABAoIBAQCDkpDs69YX3Xzd
D2wfrnlHF/q6eslYZ2Bkp66LwZ9h/NnkIo+pC95SV8h5BZrhD3khkTBx4OhSiuTU
eusxP4elc1ixqAxG/P/3K5pJ7MU1DzwevKk6sx3dhIZi8hloh9hlacYEIeLI8n8f
9TxZ9LOqx9tUXpuQXJo2nxEqqmbC1h9hkbDrrltHJyt+oL+Xt5FqusXs+0AD+2Yi
Rd9pjeY9CME7mnYDUpzkp4i00zwfG7Iq4KMMqma9K+XjbsszVKJpmzCUp7Ryyn8u
JKyRNBDzhYZtX9r9pOkVnClDtjQfcvEoYAEIHP82emkaiYPTVP710bmRh0zJfD/u
lZYrUFi1AoGBAPYdsYeQQZgELKQW/ECSxGZgo0agk7vipvaLPoFQoS1jpmEhXhTG
QmXsbgEGNaPzdep2LaMDhNw67nz1Q/lIVSnR1OONor2sy/hNZt0wq1pYTWv5NQpe
1kYX3XBbRuHzeCSLxPTSVpe/lBlIWtV2ebmb+bsc8JqqhRJ5WZfEp2T7AoGBAM2k
3IB/+Be22iF5LoGlNwlhd2s0q8VtJP8AB9Euo39aCSv2pmv4fcLqjSRuSqUsMkIe
0/QAAhqplG3NHABpBi+CkgH8ODQTxm/bpBc0xIeY/Sekcq9NZrPHwbWOACB6AxZX
c0zQoZOax78TjrlyA0HJwxoRg6iKgfc0Q/HnQmxfAoGBAOpW0Y+zklEtQFgpLpxJ
YsncH/sCsEgIglNjt+snG6B9LpFzVQJQ2C32FbPR9scZ7F+HkOKTWjDbx/KhEczM
y5IbIipc1OTnH/tXr6bSTYWjaGxzh8ZNEJcC6CywLGi+Cto5XxqBIEQy/M+p7hss
SLCrS/iWkJ2j2TsC4oS4kW57AoGAFzETiQ5ljU8a1JGVFBvs1AsA67856/7+ICAB
wa6P08n0pNehNyYEENpg5o3lrzEHzfsqDid+FUGwsp1iHg26G9uO2dh3AjCEvZK4
s8FItL4lNrZOFMUW4wmRKAeGriL0fC2KnEwfHMVk54CuJO3dviqh7SuyfGx6ccWc
MAjTreMCgYAhgweVe2FwNhvs/qiw7DX+FfCclYvZzqLA8Xjy1QdXItFYxPKucTyE
W4a7HglRepoNU0nb0GcpkY9F2GJnPgZYkeviN7A+d5QnSCpMd/qdJ4WBg3GNJTE6
U4TeWyhF0sbj2lLet5c2ujDtB7b9OAdK1HEq4DLqUD0LY4XNZCTpew==
-----END ECDSA PRIVATE KEY-----
`)
)

// DefaultMITMCertAuthorityPEM returns the default MITM Certificate authority embedded in code
func DefaultMITMCertAuthorityPEM() []byte {
	return defaultMITMCertAuthorityPEM
}

// mitmCertPool signed mitm certificate pool
var mitmCertPool sync.Map

func init() {
	mitmCertPool = sync.Map{}
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

func genECDSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
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
		SignatureAlgorithm:    x509.SHA512WithRSA,
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
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: keyDER})
	return
}

const (
	leafCertMaxAge = 3 * 30 * 24 * time.Hour
	leafCertUsage  = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment | x509.KeyUsageCRLSign | x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement
)

// SignLeafCertUsingCertAuthority signs a leaf certificate for domainNames using provided
// certificate authority default MITM certificate is used when no cert authority provided
func SignLeafCertUsingCertAuthority(certAuthority *tls.Certificate,
	domainName string) (*tls.Certificate, error) {
	if len(domainName) == 0 {
		return nil, errors.New("invalid domain name")
	}
	if cachedCert, exists := mitmCertPool.Load(domainName); exists {
		return cachedCert.(*tls.Certificate), nil
	}

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
		Subject:               pkix.Name{CommonName: domainName},
		NotBefore:             now,
		NotAfter:              now.Add(leafCertMaxAge),
		KeyUsage:              leafCertUsage,
		BasicConstraintsValid: true,
		DNSNames:              []string{domainName},
		SignatureAlgorithm:    x509.SHA512WithRSA,
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
	cachedCert, _ := mitmCertPool.LoadOrStore(domainName, cert)
	return cachedCert.(*tls.Certificate), nil
}
