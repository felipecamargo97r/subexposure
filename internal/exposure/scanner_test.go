package exposure

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"subexposure/internal/httpcheck"
	"subexposure/internal/models"
	"testing"
)

type fakeHTTP struct {
	calls    []string
	fallback bool
}

func (f *fakeHTTP) Get(ctx context.Context, u string) (httpcheck.Response, error) {
	f.calls = append(f.calls, u)
	if f.fallback && strings.HasPrefix(u, "https:") {
		return httpcheck.Response{}, errors.New("synthetic connection failure")
	}
	if strings.HasSuffix(u, "/.env") {
		return httpcheck.Response{Status: 200, Body: []byte("TOKEN=DO_NOT_PERSIST\r\nPASSWORD=ALSO_SECRET\r\n")}, nil
	}
	return httpcheck.Response{Status: 404, Body: []byte("missing")}, nil
}
func TestScanHostAndRedaction(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		f := &fakeHTTP{fallback: fallback}
		results := ScanHost(context.Background(), f, "example.com")
		found := false
		for _, r := range results {
			if r.Path == "/.env" {
				found = true
				if r.Classification != models.LikelyExposed {
					t.Fatal(r)
				}
			}
		}
		if !found {
			t.Fatal("missing env finding")
		}
		b, _ := json.Marshal(results)
		if strings.Contains(string(b), "DO_NOT_PERSIST") || strings.Contains(string(b), "ALSO_SECRET") {
			t.Fatal("secret persisted")
		}
		for _, u := range f.calls {
			if !fallback && strings.HasPrefix(u, "http:") {
				t.Fatal("HTTPS preference violated")
			}
		}
	}
}
func TestCancelledScanner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &fakeHTTP{}
	results := ScanHost(ctx, f, "example.com")
	if len(results) != 0 {
		t.Fatal(results)
	}
}
