package gobusterfuzz

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/OJ/gobuster/v3/libgobuster"
	"github.com/fatih/color"
)

var (
	green = color.New(color.FgGreen).FprintfFunc()
	blue  = color.New(color.FgBlue).FprintfFunc()
)

// Result represents a single result
type Result struct {
	Word       string
	Path       string
	Target     string
	StatusCode int
	Size       int64
	Header     http.Header
}

// ResultFields extracts the fields for the structured output
func (r Result) ResultFields() libgobuster.StructuredFields {
	return libgobuster.StructuredFields{
		Target:     r.Target,
		Path:       r.Path,
		StatusCode: r.StatusCode,
		Length:     r.Size,
		Redirect:   r.Header.Get("Location"),
	}
}

// ResultToString converts the Result to its textual representation
func (r Result) ResultToString() (string, error) {
	buf := &bytes.Buffer{}

	green(buf, "[Status=%d] [Length=%d] [Word=%s] %s", r.StatusCode, r.Size, r.Word, r.Path)

	location := r.Header.Get("Location")
	if location != "" {
		blue(buf, " [--> %s]", location)
	}

	if _, err := fmt.Fprintf(buf, "\n"); err != nil {
		return "", err
	}
	s := buf.String()
	return s, nil
}
