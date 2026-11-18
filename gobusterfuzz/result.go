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
	StatusCode int
	Size       int64
	Header     http.Header
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

// ToSARIF converts the result into stable SARIF data.
func (r Result) ToSARIF() libgobuster.SARIFFinding {
	properties := map[string]string{
		"statusCode": fmt.Sprintf("%d", r.StatusCode),
		"size":       fmt.Sprintf("%d", r.Size),
		"word":       r.Word,
	}
	if location := r.Header.Get("Location"); location != "" {
		properties["location"] = location
	}

	return libgobuster.SARIFFinding{
		RuleID:          libgobuster.SARIFRuleForStatus(r.StatusCode),
		Message:         fmt.Sprintf("HTTP fuzzing response discovered: %s (status %d, size %d)", r.Path, r.StatusCode, r.Size),
		LogicalLocation: r.Path,
		Properties:      properties,
	}
}
