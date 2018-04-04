package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"strings"
)

// MakeClientTLSConfig make a client TLS config based on host and serverName
// serverName is 1st used to generate the config then from client tls
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

// MakeClientTLSConfigByCA make a client TLS config based on self-signed CA certificate
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
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return tlsConfig
	}
	newCert.Certificate = append(newCert.Certificate, selfCertificate)
	newCert.PrivateKey = key
	newCert.Leaf, _ = x509.ParseCertificate(selfCertificate)

	tlsConfig.Certificates = append(tlsConfig.Certificates, *newCert)
	return tlsConfig
}
