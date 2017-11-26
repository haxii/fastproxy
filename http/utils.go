package http

import "bytes"

func changeToUpperCase(s []byte) {
	for i, b := range s {
		if 'a' <= b && b <= 'z' {
			b -= 'a' - 'A'
			s[i] = b
		}
	}
}

func changeToLowerCase(s []byte) {
	for i, b := range s {
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
			s[i] = b
		}
	}
}

var methodConnect = []byte("CONNECT")

//IsMethodConnect if the method is `CONNECT`
func IsMethodConnect(method []byte) bool {
	return bytes.Equal(method, methodConnect)
}
