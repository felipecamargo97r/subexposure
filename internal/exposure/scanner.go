package exposure

import (
	"context"
	"net"
	"subexposure/internal/dns"
	"subexposure/internal/httpcheck"
	"subexposure/internal/models"
	"time"
)

type Getter interface {
	Get(context.Context, string) (httpcheck.Response, error)
}

func Classify(d Detector, path string, r httpcheck.Response, base httpcheck.Response, basePath string, baselineOK bool) Match {
	if r.Redirected || r.Status >= 300 && r.Status < 400 {
		return Match{models.Redirect, "LOW", "redirect observed; destination content not treated as source exposure"}
	}
	if r.Status == 401 || r.Status == 403 {
		return Match{models.Protected, "MEDIUM", "HTTP access denied; existence not established"}
	}
	if r.Status == 404 || r.Status == 410 {
		return Match{models.NotFound, "HIGH", "HTTP not found"}
	}
	if baselineOK && httpcheck.Same(r, path, base, basePath) {
		return Match{models.Soft404, "HIGH", "response matches two consistent missing-path baselines"}
	}
	if r.Status != 200 {
		return Match{models.Inconclusive, "LOW", "unexpected HTTP status"}
	}
	if r.Truncated {
		return Match{models.Inconclusive, "LOW", "response exceeded 64 KiB inspection limit"}
	}
	m := d.Match(path, r.Body)
	if !baselineOK && (m.Classification == models.Exposed || m.Classification == models.LikelyExposed) {
		return Match{models.Inconclusive, "LOW", "signature found but missing-path baseline unavailable or unstable"}
	}
	return m
}
func ScanHost(ctx context.Context, c Getter, host string) []models.Finding {
	var out []models.Finding
	if ctx.Err() != nil {
		return out
	}
	addErr := func(scheme, path string, err error) {
		out = append(out, models.Finding{Host: host, Scheme: scheme, Path: path, Classification: httpcheck.ErrorClass(err), Confidence: "LOW", Evidence: "request failed or blocked; raw error omitted"})
	}
	var scheme string
	for _, s := range []string{"https", "http"} {
		_, err := c.Get(ctx, s+"://"+host+"/")
		if err == nil {
			scheme = s
			break
		}
		addErr(s, "/", err)
		if ctx.Err() != nil {
			return out
		}
	}
	if scheme == "" {
		return out
	}
	origin := scheme + "://" + host
	p1, p2 := httpcheck.RandomPath(), httpcheck.RandomPath()
	b1, e1 := c.Get(ctx, origin+p1)
	b2, e2 := c.Get(ctx, origin+p2)
	baselineOK := e1 == nil && e2 == nil && !b1.Redirected && !b2.Redirected && httpcheck.Same(b1, p1, b2, p2)
	for _, d := range Detectors() {
		for _, p := range d.Paths() {
			if ctx.Err() != nil {
				return out
			}
			r, err := c.Get(ctx, origin+p)
			if err != nil {
				addErr(scheme, p, err)
				continue
			}
			m := Classify(d, p, r, b1, p1, baselineOK)
			out = append(out, models.Finding{Host: host, Scheme: scheme, Path: p, Detector: d.Name(), Classification: m.Classification, Confidence: m.Confidence, Status: r.Status, Evidence: m.Evidence})
		}
	}
	return out
}
func ResolveHost(ctx context.Context, host string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, err := dns.Resolve(ctx, net.DefaultResolver, host)
	return err
}
