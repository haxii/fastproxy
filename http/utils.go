package http

import "bytes"

var methodConnect = []byte("CONNECT")

//IsMethodConnect if the method is `CONNECT`
func IsMethodConnect(method []byte) bool {
	return bytes.Equal(method, methodConnect)
}

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

func hasPrefixIgnoreCase(s, prefix []byte) bool {
	return len(s) >= len(prefix) && equalIgnoreCase(s[0:len(prefix)], prefix)
}

//equalIgnoreCase better performance than bytes.EqualBold
func equalIgnoreCase(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, _a := range a {
		_b := b[i]
		//equals
		if _a == _b {
			continue
		}
		//_b in lower case
		if 'a' <= _b && _b <= 'z' {
			if _a == _b-('a'-'A') {
				continue
			}
		}
		//_b in upper case
		if 'A' <= _b && _b <= 'Z' {
			if _a == _b+('a'-'A') {
				continue
			}
		}
		return false
	}
	return true
}
