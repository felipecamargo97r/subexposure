package report

import (
	"encoding/json"
	"io"
	"subexposure/internal/models"
)

type Writer struct {
	w      io.Writer
	format string
	first  bool
}

func New(w io.Writer, format string) (*Writer, error) {
	r := &Writer{w, format, true}
	if format == "json" {
		_, err := io.WriteString(w, "[\n")
		return r, err
	}
	return r, nil
}
func (r *Writer) Write(f models.Finding) error {
	if r.format == "json" && !r.first {
		if _, err := io.WriteString(r.w, ",\n"); err != nil {
			return err
		}
	}
	r.first = false
	return json.NewEncoder(r.w).Encode(f)
}
func (r *Writer) Close() error {
	if r.format == "json" {
		_, err := io.WriteString(r.w, "]\n")
		return err
	}
	return nil
}
