package subfinder

import (
	"context"
	"testing"
)

func TestNoSubdomains(t *testing.T) {
	h, e := Enumerate(context.Background(), "nonexistent", "example.com", "app.example.com", true)
	if e != nil || len(h) != 1 || h[0] != "app.example.com" {
		t.Fatal(h, e)
	}
}
func TestMissingExecutable(t *testing.T) {
	if _, e := Enumerate(context.Background(), "subexposure-missing-executable", "example.com", "example.com", false); e == nil {
		t.Fatal("expected error")
	}
}
