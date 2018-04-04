package uri

import "testing"
import "bytes"

func TestParse(t *testing.T) {
	t.Fatal("test host info parseHostWithPort using all kinds of possibilities")
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
