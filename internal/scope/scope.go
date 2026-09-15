package scope

import (
	"fmt"
	"golang.org/x/net/publicsuffix"
	"net"
	"net/url"
	"strings"
)

func Normalize(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if len(host) > 253 || net.ParseIP(host) != nil {
		return "", fmt.Errorf("expected a DNS domain")
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("expected a full DNS domain")
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 63 || p[0] == '-' || p[len(p)-1] == '-' {
			return "", fmt.Errorf("invalid domain")
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("use an ASCII/punycode DNS domain")
			}
		}
	}
	return host, nil
}
func Parse(target string) (host, root string, err error) {
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, e := url.Parse(target)
	if e != nil || u == nil {
		return "", "", fmt.Errorf("invalid target")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Port() != "" {
		return "", "", fmt.Errorf("only HTTP(S) domains without credentials or custom ports are supported")
	}
	host, err = Normalize(u.Hostname())
	if err != nil {
		return
	}
	root, err = publicsuffix.EffectiveTLDPlusOne(host)
	return
}
func Contains(root, host string) bool {
	h, e := Normalize(host)
	return e == nil && (h == root || strings.HasSuffix(h, "."+root))
}
func AllowedURL(root string, u *url.URL) bool {
	return u != nil && (u.Scheme == "https" || u.Scheme == "http") && u.User == nil && (u.Port() == "" || u.Scheme == "https" && u.Port() == "443" || u.Scheme == "http" && u.Port() == "80") && Contains(root, u.Hostname())
}
