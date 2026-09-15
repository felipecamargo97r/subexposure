package report

import (
	"bytes"
	"encoding/json"
	"subexposure/internal/models"
	"testing"
)

func TestFormats(t *testing.T) {
	for _, format := range []string{"json", "jsonl"} {
		var b bytes.Buffer
		r, e := New(&b, format)
		if e != nil {
			t.Fatal(e)
		}
		for i := 0; i < 2; i++ {
			if e = r.Write(models.Finding{Classification: models.Exposed, Confidence: "HIGH", Evidence: "structural only"}); e != nil {
				t.Fatal(e)
			}
		}
		if e = r.Close(); e != nil {
			t.Fatal(e)
		}
		if format == "json" && !json.Valid(b.Bytes()) {
			t.Fatal(b.String())
		}
		if format == "jsonl" {
			for _, line := range bytes.Split(bytes.TrimSpace(b.Bytes()), []byte("\n")) {
				if !json.Valid(line) {
					t.Fatal(string(line))
				}
			}
		}
	}
}
