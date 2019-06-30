package uri

import (
	"bytes"
	"net"
	"testing"
)

func TestParse(t *testing.T) {
	//t.Fatal("test host info parseHostWithPort using all kinds of possibilities")
	u := &URI{}
	//uri1: connect www.example.com:443 http/1.1
	testURIParse(t, u, true, "www.example.com:443",
		"", "www.example.com:443", "www.example.com:443",
		"", "", "", "")
	testURIChangeHost(t, u, true, "www.example.com:443", "blog.test.com",
		"", "blog.test.com", "blog.test.com:443",
		"", "", "", "")
	testURIChangeHost(t, u, true, "www.example.com:443", "blog.test.com:334",
		"", "blog.test.com:334", "blog.test.com:334",
		"", "", "", "")
	testURIChangePath(t, u, true, "www.example.com:443", "/any/path/should?be=ignored#1",
		"", "www.example.com:443", "www.example.com:443",
		"", "", "", "")
	testURIParse(t, u, true, "www.example.com",
		"", "www.example.com", "www.example.com:443",
		"", "", "", "")
	testURIChangeHost(t, u, true, "www.example.com", "blog.test.com",
		"", "blog.test.com", "blog.test.com:443",
		"", "", "", "")
	testURIChangeHost(t, u, true, "www.example.com", "blog.test.com:334",
		"", "blog.test.com:334", "blog.test.com:334",
		"", "", "", "")
	//below test should not happen in real proxy connects though
	testURIParse(t, u, true, "www.example.com/with/path",
		"", "www.example.com", "www.example.com:443",
		"", "", "", "")
	testURIChangeHost(t, u, true, "www.example.com/with/path", "blog.test.com:334",
		"", "blog.test.com:334", "blog.test.com:334",
		"", "", "", "")
	testURIChangeHost(t, u, true, "www.example.com/with/path", "",
		"", "", "",
		"", "", "", "")

	//uri2: /path/to/resource
	testURIParse(t, u, false, "/path/to/resource",
		"", "", "",
		"/path/to/resource", "/path/to/resource", "", "")
	testURIChangeHost(t, u, false, "/path/to/resource", "www.example.com",
		"", "www.example.com", "www.example.com:80",
		"/path/to/resource", "/path/to/resource", "", "")
	testURIParse(t, u, false, "/path/to/resource?q=xx&sss=f",
		"", "", "",
		"/path/to/resource?q=xx&sss=f", "/path/to/resource", "?q=xx&sss=f", "")
	testURIParse(t, u, false, "/path/to/resource?q=xx&sss=f#fragments",
		"", "", "",
		"/path/to/resource?q=xx&sss=f#fragments", "/path/to/resource", "?q=xx&sss=f", "#fragments")
	testURIChangePath(t, u, false, "/path/to/resource?q=xx&sss=f", "/path/to/hijack?q=yy&zz=f#1",
		"", "", "",
		"/path/to/hijack?q=yy&zz=f#1", "/path/to/hijack", "?q=yy&zz=f", "#1")
	testURIChangePath(t, u, false, "/path/to/resource?q=xx&sss=f", "/",
		"", "", "",
		"/", "/", "", "")
	testURIChangePath(t, u, false, "/path/to/resource?q=xx&sss=f", "",
		"", "", "",
		"/", "/", "", "")
	testURIParse(t, u, false, "/path/to/resource#fragments",
		"", "", "",
		"/path/to/resource#fragments", "/path/to/resource", "", "#fragments")
	testURIParse(t, u, false, "/path/to/resource#fragments?q=xx&sss=f",
		"", "", "",
		"/path/to/resource#fragments?q=xx&sss=f", "/path/to/resource", "", "#fragments?q=xx&sss=f")
	testURIParse(t, u, false, "/path/to/resource?##?!",
		"", "", "",
		"/path/to/resource?##?!", "/path/to/resource", "?", "##?!")
	testURIParse(t, u, false, "path",
		"", "path", "path:80",
		"/", "/", "", "")

	//uri3: http://www.example.com
	//  http://www.example.com/path/to/resource
	testURIParse(t, u, false, "http://www.example.com",
		"http", "www.example.com", "www.example.com:80",
		"/", "/", "", "")
	testURIChangeHost(t, u, false, "http://www.example.com", "www.blog.com:8080",
		"http", "www.blog.com:8080", "www.blog.com:8080",
		"/", "/", "", "")
	testURIChangeHost(t, u, false, "http://www.example.com", "",
		"", "", "",
		"/", "/", "", "")
	testURIChangePath(t, u, false, "http://www.example.com", "/path/to/res?q=p&p=q#1",
		"http", "www.example.com", "www.example.com:80",
		"/path/to/res?q=p&p=q#1", "/path/to/res", "?q=p&p=q", "#1")
	testURIParse(t, u, false, "http://www.example.com/",
		"http", "www.example.com", "www.example.com:80",
		"/", "/", "", "")
	testURIChangePath(t, u, false, "http://www.example.com/", "/path/to/res?q=p&p=q#1",
		"http", "www.example.com", "www.example.com:80",
		"/path/to/res?q=p&p=q#1", "/path/to/res", "?q=p&p=q", "#1")
	testURIChangePath(t, u, false, "http://www.example.com/", "path/to/res?q=p&p=q#1",
		"http", "www.example.com", "www.example.com:80",
		"/path/to/res?q=p&p=q#1", "/path/to/res", "?q=p&p=q", "#1")
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

func testURIChangeHost(t *testing.T, u *URI, isConnect bool, originalURI, newHostWithPort,
	expectedScheme, expectedHost, expectedHostWithPort,
	expectedPathQueryFragment, expectedPath, expectedQuery, expectedFragment string) {
	u.Parse(isConnect, []byte(originalURI))
	u.ChangeHost(newHostWithPort)
	testURI(t, u, expectedScheme, expectedHost, expectedHostWithPort,
		expectedPathQueryFragment, expectedPath, expectedQuery, expectedFragment)

}

func testURIChangePath(t *testing.T, u *URI, isConnect bool, originalURI, newPath,
	expectedScheme, expectedHost, expectedHostWithPort,
	expectedPathQueryFragment, expectedPath, expectedQuery, expectedFragment string) {
	u.Parse(isConnect, []byte(originalURI))
	u.ChangePathWithFragment([]byte(newPath))
	testURI(t, u, expectedScheme, expectedHost, expectedHostWithPort,
		expectedPathQueryFragment, expectedPath, expectedQuery, expectedFragment)

}

func testURIParse(t *testing.T, u *URI, isConnect bool, uri,
	expectedScheme, expectedHost, expectedHostWithPort,
	expectedPathQueryFragment, expectedPath, expectedQuery, expectedFragment string) {
	u.Parse(isConnect, []byte(uri))
	testURI(t, u, expectedScheme, expectedHost, expectedHostWithPort,
		expectedPathQueryFragment, expectedPath, expectedQuery, expectedFragment)
}

func testURI(t *testing.T, u *URI, expectedScheme, expectedHost, expectedHostWithPort,
	expectedPathQueryFragment, expectedPath, expectedQuery, expectedFragment string) {

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
	testHostInfo(t, "127.0.0.1:80", false, "127.0.0.1", "80", "127.0.0.1:80", "127.0.0.1:80", "127.0.0.1", "", hostInfo)
	testHostInfo(t, "127.0.0.1", true, "127.0.0.1", "443", "127.0.0.1:443", "127.0.0.1:443", "127.0.0.1", "", hostInfo)

	testHostInfo(t, "127.0.0.1:8080", false, "127.0.0.1", "8080", "127.0.0.1:8080", "127.0.0.1:8080", "127.0.0.1", "", hostInfo)
	testHostInfo(t, "127.0.0.1:444", true, "127.0.0.1", "444", "127.0.0.1:444", "127.0.0.1:444", "127.0.0.1", "", hostInfo)

	testHostInfo(t, "127.0.0.1", false, "127.0.0.1", "80", "127.0.0.1:80", "114.114.114.114:80", "114.114.114.114", "114.114.114.114", hostInfo)
	testHostInfo(t, "127.0.0.1", true, "127.0.0.1", "443", "127.0.0.1:443", "114.114.114.114:443", "114.114.114.114", "114.114.114.114", hostInfo)

	testHostInfo(t, "localhost", true, "localhost", "443", "localhost:443", "localhost:443", "localhost", "", hostInfo)
	testHostInfo(t, "localhost", false, "localhost", "80", "localhost:80", "localhost:80", "localhost", "", hostInfo)

	testHostInfo(t, "localhost:8080", false, "localhost", "8080", "localhost:8080", "localhost:8080", "localhost", "", hostInfo)
	testHostInfo(t, "localhost:445", true, "localhost", "445", "localhost:445", "localhost:445", "localhost", "", hostInfo)

	testHostInfo(t, ":::::", true, "", "", "", "", "", "", hostInfo)
	testHostInfo(t, ":::::", false, "", "", "", "", "", "", hostInfo)

}

func testHostInfo(t *testing.T, host string, isTLS bool, domain, port, hostWithPort, targetWithPort, expIP string, ipSetting string, h *HostInfo) {

	h.ParseHostWithPort(host, isTLS)
	if len(ipSetting) != 0 {
		ip := net.ParseIP(ipSetting)
		h.SetIP(ip)
	}
	if h.Domain() != domain {
		t.Fatal("Domain is wrong")
	}
	if h.HostWithPort() != hostWithPort {
		t.Fatal("Host with port is wrong")
	}

	if !bytes.Equal(h.IP(), []byte(expIP)) {
		if expIP != "localhost" && expIP != h.IP().String() {
			t.Fatal("Setting IP is wrong")
		}
	}

	if h.Port() != port {
		t.Fatal("Parsing port is wrong")
	}

	if h.TargetWithPort() != targetWithPort {
		t.Fatal("Parsing target with port error")
	}
	h.reset()

}
