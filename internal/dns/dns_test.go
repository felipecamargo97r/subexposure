package dns

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type fake []netip.Addr

func (f fake) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) { return f, nil }
func TestPublic(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.1.1", "172.16.0.1", "192.168.1.1", "192.0.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "0.0.0.0", "::", "::1", "fc00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "2001:db8::1", "2002:7f00:1::", "3fff::1"} {
		if Public(netip.MustParseAddr(s)) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !Public(netip.MustParseAddr(s)) {
			t.Fatal(s)
		}
	}
}
func TestMixedRejected(t *testing.T) {
	_, e := Resolve(context.Background(), fake{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, "example.com")
	if !errors.Is(e, ErrBlocked) {
		t.Fatal(e)
	}
}
