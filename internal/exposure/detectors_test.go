package exposure

import (
	"encoding/json"
	"strings"
	"subexposure/internal/httpcheck"
	"subexposure/internal/models"
	"testing"
)

func TestSignaturesAndRedaction(t *testing.T) {
	cases := map[string]string{"/.git/HEAD": "ref: refs/heads/main\n", "/.git/config": "[core]\nrepositoryformatversion = 0\npassword=SUPERSECRET", "/.env": "TOKEN=SUPERSECRET\nPASSWORD=other-secret", "/.hg/requires": "revlogv1\nstore\n", "/.svn/entries": "10\n\ndir\n", "/.svn/wc.db": "SQLite format 3\x00SUPERSECRET"}
	for _, d := range Detectors() {
		for _, p := range d.Paths() {
			m := d.Match(p, []byte(cases[p]))
			if m.Classification != models.Exposed && m.Classification != models.LikelyExposed {
				t.Fatalf("%s: %+v", p, m)
			}
			b, _ := json.Marshal(m)
			if strings.Contains(string(b), "SUPERSECRET") || strings.Contains(string(b), "other-secret") {
				t.Fatal("secret leak")
			}
			if d.Match(p, []byte("<html>KEY=VALUE</html>")).Classification != models.Inconclusive {
				t.Fatal(p)
			}
		}
	}
}
func TestBaselinePrecedence(t *testing.T) {
	d := Detectors()[0]
	r := httpcheck.Response{Status: 200, Body: []byte("ref: refs/heads/main")}
	if m := Classify(d, "/.git/HEAD", r, r, "/missing", true); m.Classification != models.Soft404 {
		t.Fatal(m)
	}
	if m := Classify(d, "/.git/HEAD", r, r, "/missing", false); m.Classification != models.Inconclusive {
		t.Fatal(m)
	}
	r.Truncated = true
	if m := Classify(d, "/.git/HEAD", r, r, "/missing", true); m.Classification != models.Inconclusive {
		t.Fatal(m)
	}
}
