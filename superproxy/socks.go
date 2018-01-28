package superproxy

import (
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/haxii/fastproxy/bytebufferpool"
)

const socks5Version = 5

const (
	socks5AuthNone     = 0
	socks5AuthPassword = 2
)

const socks5Connect = 1

const (
	socks5IP4    = 1
	socks5Domain = 3
	socks5IP6    = 4
)

var socks5Errors = []string{
	"",
	"general failure",
	"connection forbidden",
	"network unreachable",
	"host unreachable",
	"connection refused",
	"TTL expired",
	"command not supported",
	"address type not supported",
}

func (p *SuperProxy) initSOCKS5GreetingsAndAuth(user string, pass string) {
	p.socks5Greetings = make([]byte, 0, 4)
	p.socks5Greetings = append(p.socks5Greetings, socks5Version)
	if len(user) > 0 && len(user) < 256 && len(pass) < 256 {
		p.socks5Greetings = append(p.socks5Greetings, 2, /* num auth methods */
			socks5AuthNone, socks5AuthPassword)
		// socks5 auth
		p.socks5Auth = make([]byte, 0, 3+len(user)+len(pass))
		p.socks5Auth = append(p.socks5Auth, 1 /* password protocol version */)
		p.socks5Auth = append(p.socks5Auth, uint8(len(user)))
		p.socks5Auth = append(p.socks5Auth, user...)
		p.socks5Auth = append(p.socks5Auth, uint8(len(pass)))
		p.socks5Auth = append(p.socks5Auth, pass...)
	} else {
		p.socks5Greetings = append(p.socks5Greetings, 1, /* num auth methods */
			socks5AuthNone)
	}
}

// connect takes an existing connection to a socks5 proxy server,
// and commands the server to extend that connection to target,
// which must be a canonical address with a host and port.
func (p *SuperProxy) connectSOCKS5Proxy(conn net.Conn, targetHost string, targetPort int) error {
	if _, err := conn.Write(p.socks5Greetings); err != nil {
		return errors.New("proxy: failed to write greeting to SOCKS5 proxy at " +
			p.hostWithPort + ": " + err.Error())
	}
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)
	buf.Write([]byte{0, 0})

	//TODO: use bufio instead?
	if _, err := io.ReadFull(conn, buf.B[:2]); err != nil {
		return errors.New("proxy: failed to read greeting from SOCKS5 proxy at " +
			p.hostWithPort + ": " + err.Error())
	}
	if buf.B[0] != 5 {
		return errors.New("proxy: SOCKS5 proxy at " +
			p.hostWithPort + " has unexpected version " + strconv.Itoa(int(buf.B[0])))
	}
	if buf.B[1] == 0xff {
		return errors.New("proxy: SOCKS5 proxy at " +
			p.hostWithPort + " requires authentication")
	}

	// See RFC 1929
	if buf.B[1] == socks5AuthPassword {
		if _, err := conn.Write(p.socks5Auth); err != nil {
			return errors.New("proxy: failed to write authentication request to SOCKS5 proxy at " +
				p.hostWithPort + ": " + err.Error())
		}

		if _, err := io.ReadFull(conn, buf.B[:2]); err != nil {
			return errors.New("proxy: failed to read authentication reply from SOCKS5 proxy at " +
				p.hostWithPort + ": " + err.Error())
		}

		if buf.B[1] != 0 {
			return errors.New("proxy: SOCKS5 proxy at " +
				p.hostWithPort + " rejected username/password")
		}
	}

	buf.Reset()
	buf.WriteByte(socks5Version)
	buf.WriteByte(socks5Connect)
	buf.WriteByte(0) /* reserved */

	if ip := net.ParseIP(targetHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(socks5IP4)
			ip = ip4
		} else {
			buf.WriteByte(socks5IP6)
		}
		buf.Write(ip)
	} else {
		if len(targetHost) > 255 {
			return errors.New("proxy: destination host name too long: " + targetHost)
		}
		buf.WriteByte(socks5Domain)
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
	}
	buf.WriteByte(byte(targetPort >> 8))
	buf.WriteByte(byte(targetPort))

	if _, err := conn.Write(buf.B); err != nil {
		return errors.New("proxy: failed to write connect request to SOCKS5 proxy at " +
			p.hostWithPort + ": " + err.Error())
	}

	if _, err := io.ReadFull(conn, buf.B[:4]); err != nil {
		return errors.New("proxy: failed to read connect reply from SOCKS5 proxy at " +
			p.hostWithPort + ": " + err.Error())
	}

	failure := "unknown error"
	if int(buf.B[1]) < len(socks5Errors) {
		failure = socks5Errors[buf.B[1]]
	}

	if len(failure) > 0 {
		return errors.New("proxy: SOCKS5 proxy at " +
			p.hostWithPort + " failed to connect: " + failure)
	}

	bytesToDiscard := 0
	switch buf.B[3] {
	case socks5IP4:
		bytesToDiscard = net.IPv4len
	case socks5IP6:
		bytesToDiscard = net.IPv6len
	case socks5Domain:
		_, err := io.ReadFull(conn, buf.B[:1])
		if err != nil {
			return errors.New("proxy: failed to read domain length from SOCKS5 proxy at " +
				p.hostWithPort + ": " + err.Error())
		}
		bytesToDiscard = int(buf.B[0])
	default:
		return errors.New("proxy: got unknown address type " +
			strconv.Itoa(int(buf.B[3])) + " from SOCKS5 proxy at " + p.hostWithPort)
	}

	if cap(buf.B) < bytesToDiscard {
		buf.B = make([]byte, bytesToDiscard)
	} else {
		buf.B = buf.B[:bytesToDiscard]
	}
	if _, err := io.ReadFull(conn, buf.B); err != nil {
		return errors.New("proxy: failed to read address from SOCKS5 proxy at " +
			p.hostWithPort + ": " + err.Error())
	}

	// Also need to discard the port number
	if _, err := io.ReadFull(conn, buf.B[:2]); err != nil {
		return errors.New("proxy: failed to read port from SOCKS5 proxy at " +
			p.hostWithPort + ": " + err.Error())
	}

	return nil
}
