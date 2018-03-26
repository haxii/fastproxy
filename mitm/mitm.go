package x509

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

//DefaultMitmCA used for mitm
var DefaultMitmCA *tls.Certificate

func init() {
	//make ca for https
	if cer, err := tls.X509KeyPair(RootCERT, rootKEY); err == nil {
		DefaultMitmCA = &cer
		if DefaultMitmCA.Leaf, err = x509.ParseCertificate(DefaultMitmCA.Certificate[0]); err != nil {
			fmt.Printf("|FATAL| unable to make CA leaf for mitm, error %s", err)
			os.Exit(1)
			return
		}
	} else {
		fmt.Printf("|FATAL| unable to load CA for mitm, error %s", err)
		os.Exit(1)
		return
	}
}

// RootCERT cert file in bytes
var RootCERT = []byte(`-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`)

var rootKEY = []byte(`-----BEGIN ECDSA PRIVATE KEY-----
MIHcAgEBBEIA1FCmb8JkZ8UBiLyZ3zaLE5ibDC+Y3BarrjssCkzPK7mtEOpbctqh
d0QGEvlOkv8bzp2J+Iw4iZBmCX81YtQyfCGgBwYFK4EEACOhgYkDgYYABAGVr9JH
Bx3sGRZ62wb4vjsjgf0e9AQqhNxO7m7uASsHPoiXsfdV0GD/gXKfrsNgtvm8FBQM
AtuVsgTgfqJPji2jwgC7xTpZB8BFflW4t6G86ifD87fXLNzcuFgov5N8pomYMSyr
aVEWvZZ6Hl2VjL32ZkH/iDQpZKacJLwaaYpYMX39UA==
-----END ECDSA PRIVATE KEY-----`)
