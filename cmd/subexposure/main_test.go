package main

import (
	"bytes"
	"testing"
)

func TestInvalidFlags(t *testing.T) {
	for _, args := range [][]string{{"scan", "example.com", "--workers", "51"}, {"scan", "example.com", "--rate", "NaN"}, {"scan", "example.com", "--timeout", "0s"}, {"scan", "example.com", "--format", "csv"}, {"scan", "example.com", "--resume"}, {"scan", "http://127.0.0.1", "--no-subdomains"}} {
		var b bytes.Buffer
		if code := run(args, &b, &b); code != 2 {
			t.Fatal(args, code)
		}
	}
}
