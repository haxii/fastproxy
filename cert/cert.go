package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/haxii/fastproxy/util"
)

const (
	caMaxAge   = 5 * 365 * 24 * time.Hour
	leafMaxAge = 24 * time.Hour
	caUsage    = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	leafUsage = caUsage
)

//GenCert gen host's certificate
func GenCert(ca *tls.Certificate, names []string) (*tls.Certificate, error) {
	now := time.Now().Add(-1 * time.Hour).UTC()
	if !ca.Leaf.IsCA {
		return nil, errors.New("CA cert is not a CA")
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, util.ErrWrapper(err, "failed to generate serial number")
	}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now,
		NotAfter:              now.Add(leafMaxAge),
		KeyUsage:              leafUsage,
		BasicConstraintsValid: true,
		DNSNames:              names,
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
	}
	key, err := genKeyPair()
	if err != nil {
		return nil, err
	}
	x, err := x509.CreateCertificate(rand.Reader, template, ca.Leaf, key.Public(), ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.PrivateKey = key
	cert.Leaf, _ = x509.ParseCertificate(x)
	return cert, nil
}

func genKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

//GenCA gen a new root ca.cer and private key
func GenCA(name string) (certPEM, keyPEM []byte, err error) {
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(caMaxAge),
		KeyUsage:              caUsage,
		BasicConstraintsValid: true,
		IsCA:               true,
		MaxPathLen:         2,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}
	key, err := genKeyPair()
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
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: keyDER,
	})
	return
}

//MakeClientTLSConfig make a client TLS config based on host and servername
//servername is 1st used to generate the config then from client tls
func MakeClientTLSConfig(host, serverName string) *tls.Config {
	tlsServerName := func(addr string) string {
		if len(addr) == 0 {
			return "*"
		}
		if !strings.Contains(addr, ":") {
			return addr
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return "*"
		}
		return host
	}
	tlsConfig := &tls.Config{}
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)

	if len(serverName) == 0 {
		hostName := tlsServerName(host)
		if hostName == "*" {
			tlsConfig.InsecureSkipVerify = true
		} else {
			tlsConfig.ServerName = hostName
		}
	} else {
		tlsConfig.ServerName = serverName
	}
	return tlsConfig
}

// MakeClientTLSConfigByCA make a client TLS config based on self-signed ca certificate
func MakeClientTLSConfigByCA(host, serverName, filePath string) *tls.Config {
	tlsServerName := func(addr string) string {
		if len(addr) == 0 {
			return "*"
		}
		if !strings.Contains(addr, ":") {
			return addr
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return "*"
		}
		return host
	}
	tlsConfig := &tls.Config{}
	tlsConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)

	if len(serverName) == 0 {
		hostName := tlsServerName(host)
		if hostName == "*" {
			tlsConfig.InsecureSkipVerify = true
		} else {
			tlsConfig.ServerName = hostName
		}
	} else {
		tlsConfig.ServerName = serverName
	}
	selfCertificate, err := ioutil.ReadFile(filePath)
	if err != nil {
		return tlsConfig
	}
	newCert := &tls.Certificate{}
	key, err := genKeyPair()
	if err != nil {
		return tlsConfig
	}
	newCert.Certificate = append(newCert.Certificate, selfCertificate)
	newCert.PrivateKey = key
	newCert.Leaf, _ = x509.ParseCertificate(selfCertificate)

	tlsConfig.Certificates = append(tlsConfig.Certificates, *newCert)
	return tlsConfig
}
