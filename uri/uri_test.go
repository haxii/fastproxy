package uri

import "testing"
import "bytes"

func TestParse(t *testing.T) {
	//t.Fatal("test host info parseHostWithPort using all kinds of possibilities")
	u := &URI{}
	//uri1: connect www.example.com:443 http/1.1
	testURIParse(t, u, true, "www.example.com:443",
		"", "www.example.com:443", "www.example.com:443",
		"", "", "", "")
	testURIParse(t, u, true, "www.example.com",
		"", "www.example.com", "www.example.com:443",
		"", "", "", "")
	//below test should not happen in real proxy connects though
	testURIParse(t, u, true, "www.example.com/with/path",
		"", "www.example.com", "www.example.com:443",
		"", "", "", "")

	//uri2: /path/to/resource
	testURIParse(t, u, false, "/path/to/resource",
		"", "", "",
		"/path/to/resource", "/path/to/resource", "", "")
	testURIParse(t, u, false, "/path/to/resource?q=xx&sss=f",
		"", "", "",
		"/path/to/resource?q=xx&sss=f", "/path/to/resource", "?q=xx&sss=f", "")
	testURIParse(t, u, false, "/path/to/resource?q=xx&sss=f#fragments",
		"", "", "",
		"/path/to/resource?q=xx&sss=f#fragments", "/path/to/resource", "?q=xx&sss=f", "#fragments")
	testURIParse(t, u, false, "/path/to/resource#fragments",
		"", "", "",
		"/path/to/resource#fragments", "/path/to/resource", "", "#fragments")
	testURIParse(t, u, false, "/path/to/resource#fragments?q=xx&sss=f",
		"", "", "",
		"/path/to/resource#fragments?q=xx&sss=f", "/path/to/resource", "", "#fragments?q=xx&sss=f")
	testURIParse(t, u, false, "/path/to/resource?##?!",
		"", "", "",
		"/path/to/resource?##?!", "/path/to/resource", "?", "##?!")
	//TODO: is this a bug?
	testURIParse(t, u, false, "path/to/resource",
		"", "path", "path:80",
		"/to/resource", "/to/resource", "", "")
	testURIParse(t, u, false, "path",
		"", "path", "path:80",
		"/", "/", "", "")

	//uri3: http://www.example.com
	//  http://www.example.com/path/to/resource
	testURIParse(t, u, false, "http://www.example.com",
		"http", "www.example.com", "www.example.com:80",
		"/", "/", "", "")
	testURIParse(t, u, false, "http://www.example.com/",
		"http", "www.example.com", "www.example.com:80",
		"/", "/", "", "")
	testURIParse(t, u, false, "http://www.example.com?q=123",
		"http", "www.example.com", "www.example.com:80",
		"?q=123", "/", "?q=123", "")
	testURIParse(t, u, false, "http://www.example.com?q=123#frag=456",
		"http", "www.example.com", "www.example.com:80",
		"?q=123#frag=456", "/", "?q=123", "#frag=456")
	testURIParse(t, u, false, "http://www.example.com/path/to/resource",
		"http", "www.example.com", "www.example.com:80",
		"/path/to/resource", "/path/to/resource", "", "")
	testURIParse(t, u, false, "www.example.com/path/to/resource",
		"", "www.example.com", "www.example.com:80",
		"/path/to/resource", "/path/to/resource", "", "")
}

func testURIParse(t *testing.T, u *URI, isConnect bool, uri,
	expectedScheme, expectedHost, expectedHostWithPort,
	expectedPathQueryFragment, expectedPath, expectedQuery, expectedFragment string) {
	u.Parse(isConnect, []byte(uri))
	if !bytes.Equal(u.Scheme(), []byte(expectedScheme)) {
		t.Fatalf("Unexpected Scheme %q, Expected %q", u.Scheme(), []byte(expectedScheme))
	}
	if !bytes.Equal(u.Host(), []byte(expectedHost)) {
		t.Fatalf("Unexpected Host %q, Expected %q", u.Host(), []byte(expectedHost))
	}
	if u.hostInfo.HostWithPort() != expectedHostWithPort {
		t.Fatalf("Unexpected HostWithPort %q, Expected %q", u.hostInfo.HostWithPort(), expectedHostWithPort)
	}
	if !bytes.Equal(u.PathWithQueryFragment(), []byte(expectedPathQueryFragment)) {
		t.Fatalf("Unexpected PathWithQueryFragment %q, Expected %q", u.PathWithQueryFragment(), []byte(expectedPathQueryFragment))
	}
	if !bytes.Equal(u.Path(), []byte(expectedPath)) {
		t.Fatalf("Unexpected Path %q, Expected %q", u.Path(), []byte(expectedPath))
	}
	if !bytes.Equal(u.Queries(), []byte(expectedQuery)) {
		t.Fatalf("Unexpected Queries %q, Expected %q", u.Queries(), []byte(expectedQuery))
	}
	if !bytes.Equal(u.Fragments(), []byte(expectedFragment)) {
		t.Fatalf("Unexpected Fragments %q, Expected %q", u.Fragments(), []byte(expectedFragment))
	}
}

func TestHostInfo(t *testing.T) {
	hostInfo := &HostInfo{}
	hostInfo.ParseHostWithPort("127.0.0.1:8080", false)
	hostInfo.SetIP([]byte("114.114.114.114"))

	if hostInfo.HostWithPort() != "127.0.0.1:8080" {
		t.Fatal("Host with port is wrong")
	}

	if !bytes.Equal(hostInfo.IP(), []byte("114.114.114.114")) {
		t.Fatal("Setting IP is wrong")
	}

	if hostInfo.Port() != "8080" {
		t.Fatal("Parsing port is wrong")
	}

	hostInfo.reset()
	if hostInfo.Port() == "8080" {
		t.Fatal("reset host info is wrong")
	}
	if hostInfo.HostWithPort() == "127.0.0.1:8080" {
		t.Fatal("reset host info is wrong")
	}

	if bytes.Equal(hostInfo.IP(), []byte("114.114.114.114")) {
		t.Fatal("reset host info is wrong")
	}

	hostInfo.ParseHostWithPort("localhost", true)
	hostInfo.SetIP([]byte("114.114.115.115"))
	if hostInfo.HostWithPort() != "localhost:443" {
		t.Fatal("Host with port is wrong")
	}

	if !bytes.Equal(hostInfo.IP(), []byte("114.114.115.115")) {
		t.Fatal("Setting IP is wrong")
	}

	if hostInfo.Port() != "443" {
		t.Fatal("Parsing port is wrong")
	}
	if hostInfo.Domain() != "localhost" {
		t.Fatal("Parsing host domain error")
	}

	hostInfo.reset()
	hostInfo.ParseHostWithPort("localhost", false)
	if hostInfo.HostWithPort() != "localhost:80" {
		t.Fatal("Host with port is wrong")
	}
	if hostInfo.Port() != "80" {
		t.Fatal("Parsing port is wrong")
	}
	if hostInfo.Domain() != "localhost" {
		t.Fatal("Parsing host domain error")
	}

	hostInfo.reset()
	hostInfo.ParseHostWithPort("127.0.0.1", false)
	if hostInfo.HostWithPort() != "127.0.0.1:80" {
		t.Fatal("Host with port is wrong")
	}
	if hostInfo.Port() != "80" {
		t.Fatal("Parsing port is wrong")
	}
	if hostInfo.Domain() != "127.0.0.1" {
		t.Fatal("Parsing host domain error")
	}

	hostInfo.reset()
	hostInfo.ParseHostWithPort("127.0.0.1", true)
	if hostInfo.HostWithPort() != "127.0.0.1:443" {
		t.Fatal("Host with port is wrong")
	}
	if hostInfo.Port() != "443" {
		t.Fatal("Parsing port is wrong")
	}
	if hostInfo.Domain() != "127.0.0.1" {
		t.Fatal("Parsing host domain error")
	}

	hostInfo.reset()
	hostInfo.ParseHostWithPort("", true)
	if hostInfo.HostWithPort() == ":443" {
		t.Fatal("Host with port is wrong")
	}
	if hostInfo.Port() == "443" {
		t.Fatal("Parsing port is wrong")
	}

	hostInfo.reset()
	hostInfo.ParseHostWithPort(":::::::1", true)
	if hostInfo.HostWithPort() == ":::::::1:443" {
		t.Fatal("Host with port is wrong")
	}
	if hostInfo.Port() == "443" {
		t.Fatal("Parsing port is wrong")
	}
}
