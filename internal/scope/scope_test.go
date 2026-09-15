package scope

import (
	"net/url"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tt := range []struct{ in, host, root string }{{"https://App.Example.com/path?q=secret", "app.example.com", "example.com"}, {"x.example.co.uk", "x.example.co.uk", "example.co.uk"}, {"foo.github.io", "foo.github.io", "foo.github.io"}} {
		h, r, e := Parse(tt.in)
		if e != nil || h != tt.host || r != tt.root {
			t.Fatalf("%s: %s %s %v", tt.in, h, r, e)
		}
	}
}
func TestScope(t *testing.T) {
	for _, s := range []string{"example.com.evil.org", "evil-example.com", "127.0.0.1", "*.example.com"} {
		if Contains("example.com", s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"http://user:pass@example.com", "ftp://example.com", "http://example.com:8080"} {
		u, _ := url.Parse(s)
		if AllowedURL("example.com", u) {
			t.Fatal(s)
		}
	}
}
func TestInvalid(t *testing.T) {
	for _, s := range []string{"localhost", "127.0.0.1", "https://a:b@example.com", "https://example.com:8080", "https://-bad.com", "com"} {
		if _, _, e := Parse(s); e == nil {
			t.Fatal(s)
		}
	}
}
