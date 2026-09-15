package httpcheck

import (
	"context"
	"errors"
	"golang.org/x/time/rate"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"subexposure/internal/dns"
	"testing"
	"time"
)

type resolver struct{ ip string }

func (r resolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr(r.ip)}, nil
}
func harness(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := New("example.com", time.Second, rate.NewLimiter(10000, 1))
	c.resolver = resolver{"8.8.8.8"}
	c.client.Transport = &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}}
	t.Cleanup(c.Close)
	return c
}
func TestRedirects(t *testing.T) {
	for _, tt := range []struct {
		name, to string
		blocked  bool
	}{{"external", "http://evil.org/", true}, {"internal", "http://127.0.0.1/", true}, {"loop", "http://example.com/start", true}, {"allowed", "http://sub.example.com/end", false}} {
		t.Run(tt.name, func(t *testing.T) {
			c := harness(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/end" {
					w.Write([]byte("ok"))
					return
				}
				http.Redirect(w, r, tt.to, 302)
			})
			res, e := c.Get(context.Background(), "http://example.com/start")
			if tt.blocked && !errors.Is(e, ErrRedirect) {
				t.Fatal(e)
			}
			if !tt.blocked && (e != nil || !res.Redirected) {
				t.Fatal(res, e)
			}
		})
	}
}
func TestRedirectDNSRevalidation(t *testing.T) {
	c := harness(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://sub.example.com/end", 302) })
	c.resolver = resolver{"10.0.0.1"}
	_, e := c.Get(context.Background(), "http://example.com/start")
	if !errors.Is(e, dns.ErrBlocked) {
		t.Fatal(e)
	}
}
func TestBodyLimit(t *testing.T) {
	c := harness(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", MaxBody+100))) })
	r, e := c.Get(context.Background(), "http://example.com/")
	if e != nil || !r.Truncated || len(r.Body) != MaxBody {
		t.Fatal(len(r.Body), e)
	}
}
func TestTimeout(t *testing.T) {
	c := harness(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	c.timeout = 20 * time.Millisecond
	_, e := c.Get(context.Background(), "http://example.com/")
	if e == nil || ErrorClass(e) != "TIMEOUT" {
		t.Fatal(e)
	}
}
func TestSoft404(t *testing.T) {
	c := harness(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("missing " + r.URL.Path)) })
	a, _ := c.Get(context.Background(), "http://example.com/a")
	b, _ := c.Get(context.Background(), "http://example.com/b")
	if !Same(a, "/a", b, "/b") {
		t.Fatal("reflected path baseline mismatch")
	}
}
func TestProductionBlocksLocal(t *testing.T) {
	c := New("example.com", time.Second, rate.NewLimiter(100, 1))
	defer c.Close()
	_, e := c.Get(context.Background(), "http://127.0.0.1/")
	if !errors.Is(e, dns.ErrBlocked) {
		t.Fatal(e)
	}
}
