package httpcheck

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/time/rate"
	"io"
	"net"
	"net/http"
	"strings"
	"subexposure/internal/dns"
	"subexposure/internal/models"
	"subexposure/internal/scope"
	"time"
)

const MaxBody = 64 * 1024

var ErrRedirect = errors.New("redirect blocked or limit exceeded")

type Response struct {
	Status     int
	Body       []byte
	Truncated  bool
	Redirected bool
}
type Client struct {
	client   *http.Client
	limiter  *rate.Limiter
	root     string
	timeout  time.Duration
	resolver dns.Resolver
}

func New(root string, timeout time.Duration, limiter *rate.Limiter) *Client {
	r := net.DefaultResolver
	tr := &http.Transport{Proxy: nil, DialContext: dns.Dialer(r), DisableCompression: true, MaxIdleConns: 100, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 32 * 1024}
	c := &Client{root: root, timeout: timeout, limiter: limiter, resolver: r}
	c.client = &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// Do not forward query strings from previous locations through Referer.
		req.Header.Del("Referer")
		if len(via) > 5 || !scope.AllowedURL(root, req.URL) {
			return ErrRedirect
		}
		if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme == "http" {
			return ErrRedirect
		}
		// Revalidate even if the transport could reuse an established connection.
		if _, err := dns.Resolve(req.Context(), c.resolver, req.URL.Hostname()); err != nil {
			return err
		}
		return limiter.Wait(req.Context())
	}}
	return c
}
func (c *Client) Close() { c.client.CloseIdleConnections() }
func (c *Client) Get(ctx context.Context, address string) (Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return Response{}, err
	}
	if !scope.AllowedURL(c.root, req.URL) {
		return Response{}, dns.ErrBlocked
	}
	if err = c.limiter.Wait(ctx); err != nil {
		return Response{}, err
	}
	req.Header.Set("User-Agent", "SubExposure/0.1 (authorized exposure audit)")
	res, err := c.client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxBody+1))
	if err != nil {
		return Response{}, err
	}
	truncated := len(b) > MaxBody
	if truncated {
		b = b[:MaxBody]
	}
	return Response{res.StatusCode, b, truncated, res.Request.Response != nil}, nil
}
func ErrorClass(err error) models.Classification {
	if errors.Is(err, ErrRedirect) {
		return models.Redirect
	}
	if errors.Is(err, dns.ErrBlocked) {
		return models.Inconclusive
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) || strings.Contains(err.Error(), "would exceed context deadline") {
		return models.Timeout
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		return models.DNSUnresolved
	}
	if errors.Is(err, context.Canceled) {
		return models.Inconclusive
	}
	return models.ConnectionError
}
func RandomPath() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "/.subexposure-missing-" + hex.EncodeToString(b[:])
}

// Canonicalize reflected request paths, allowing common dynamic soft-404 pages.
func canonical(b []byte, path string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(string(b), path, "<path>")), " ")
}
func Same(a Response, ap string, b Response, bp string) bool {
	return !a.Truncated && !b.Truncated && a.Status == b.Status && canonical(a.Body, ap) == canonical(b.Body, bp)
}
