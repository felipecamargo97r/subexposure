package exposure

import (
	"bytes"
	"regexp"
	"strings"
	"subexposure/internal/models"
)

type Match struct {
	Classification models.Classification
	Confidence     string
	Evidence       string
}
type Detector interface {
	Name() string
	Paths() []string
	Match(path string, body []byte) Match
}
type signature struct {
	name  string
	paths []string
}

func (d signature) Name() string    { return d.name }
func (d signature) Paths() []string { return append([]string(nil), d.paths...) }

var envLine = regexp.MustCompile(`(?m)^(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=[^\r\n]*$`)
var gitHead = regexp.MustCompile(`^(?:ref: refs/[A-Za-z0-9_./-]+|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$`)

func (d signature) Match(path string, body []byte) Match {
	no := Match{models.Inconclusive, "LOW", "no recognized structural signature"}
	if bytes.Contains(bytes.ToLower(body), []byte("<html")) || bytes.Contains(bytes.ToLower(body), []byte("<!doctype")) {
		return no
	}
	s := strings.TrimSpace(strings.ReplaceAll(string(body), "\r\n", "\n"))
	switch path {
	case "/.git/HEAD":
		if gitHead.MatchString(s) {
			return Match{models.Exposed, "HIGH", "Git HEAD reference signature"}
		}
	case "/.git/config":
		if strings.Contains(s, "[core]") && regexp.MustCompile(`(?m)^\s*repositoryformatversion\s*=\s*\d+\s*$`).MatchString(s) {
			return Match{models.Exposed, "HIGH", "Git core configuration signature; values omitted"}
		}
	case "/.env":
		if len(envLine.FindAllString(s, -1)) >= 2 {
			return Match{models.LikelyExposed, "MEDIUM", "multiple KEY=[REDACTED] assignments; names and values omitted"}
		}
	case "/.hg/requires":
		known := map[string]bool{"revlogv1": true, "store": true, "fncache": true, "dotencode": true, "generaldelta": true, "share-safe": true, "sparserevlog": true, "revlog-compression-zstd": true}
		count := 0
		for _, line := range strings.Split(s, "\n") {
			if known[strings.TrimSpace(line)] {
				count++
				delete(known, strings.TrimSpace(line))
			}
		}
		if count >= 2 {
			return Match{models.Exposed, "HIGH", "Mercurial requirements signature"}
		}
	case "/.svn/entries":
		if strings.HasPrefix(s, "<?xml") && strings.Contains(s, "<wc-entries") || regexp.MustCompile(`(?s)^\d+\n\n(?:dir|file)(?:\n|$)`).MatchString(s) {
			return Match{models.Exposed, "HIGH", "SVN entries signature"}
		}
	case "/.svn/wc.db":
		if bytes.HasPrefix(body, []byte("SQLite format 3\x00")) {
			return Match{models.LikelyExposed, "MEDIUM", "SQLite header at SVN database path; database not queried"}
		}
	}
	return no
}
func Detectors() []Detector {
	return []Detector{signature{"Git", []string{"/.git/HEAD", "/.git/config"}}, signature{"Env", []string{"/.env"}}, signature{"SVN", []string{"/.svn/entries", "/.svn/wc.db"}}, signature{"Mercurial", []string{"/.hg/requires"}}}
}
