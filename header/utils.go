package header

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
