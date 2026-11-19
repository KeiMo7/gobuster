package gobusterfuzz

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"

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
	// FullURL is the canonical target URL (stable mode only).
	FullURL *url.URL
	// Chain is the recorded redirect chain (stable mode only).
	Chain *libgobuster.RedirectChain
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

// StableKey returns the normalized target identity used for deduplication.
func (r Result) StableKey() string {
	return libgobuster.CanonicalHTTPKey(r.FullURL)
}

// StableRecord converts the result to the mode independent stable record.
func (r Result) StableRecord() libgobuster.StableRecord {
	rec := libgobuster.StableRecord{
		Key:      r.StableKey(),
		Target:   r.Path,
		Statuses: []int{r.StatusCode},
		Sizes:    []int64{r.Size},
		Location: r.Header.Get("Location"),
		Chain:    r.Chain,
		Extra:    fmt.Sprintf("Word=%s", r.Word),
	}
	if r.FullURL != nil {
		rec.Scheme = r.FullURL.Scheme
		rec.Host = r.FullURL.Host
	}
	return rec
}
