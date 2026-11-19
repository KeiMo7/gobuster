package gobusterdir

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/OJ/gobuster/v3/libgobuster"
	"github.com/fatih/color"
)

var (
	white  = color.New(color.FgWhite).FprintfFunc()
	yellow = color.New(color.FgYellow).FprintfFunc()
	green  = color.New(color.FgGreen).FprintfFunc()
	blue   = color.New(color.FgBlue).FprintfFunc()
	red    = color.New(color.FgRed).FprintfFunc()
	cyan   = color.New(color.FgCyan).FprintfFunc()
)

// Result represents a single result
type Result struct {
	Path       string
	Header     http.Header
	StatusCode int
	Size       int64
	// FullURL is the unpadded, complete target URL. It is only populated in
	// stable mode and never changes the legacy output.
	FullURL *url.URL
	// Chain is the recorded redirect chain (stable mode only).
	Chain *libgobuster.RedirectChain
	// StatusHidden and SizeHidden distinguish deliberately hidden values
	// from real zero values.
	StatusHidden bool
	SizeHidden   bool
}

// ResultToString converts the Result to its textual representation
func (r Result) ResultToString() (string, error) {
	buf := &bytes.Buffer{}
	if _, err := buf.WriteString(r.Path); err != nil {
		return "", err
	}

	if r.StatusCode >= 0 {
		textColor := white
		switch {
		case r.StatusCode == http.StatusOK:
			textColor = green
		case r.StatusCode >= 300 && r.StatusCode < 400:
			textColor = cyan
		case r.StatusCode >= 400 && r.StatusCode < 500:
			textColor = yellow
		case r.StatusCode >= 500 && r.StatusCode < 600:
			textColor = red
		}

		textColor(buf, " (Status: %d)", r.StatusCode)
	}

	if r.Size >= 0 {
		if _, err := fmt.Fprintf(buf, " [Size: %d]", r.Size); err != nil {
			return "", err
		}
	}

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
	target := r.Path
	if r.FullURL != nil {
		// never carry the legacy fixed width padding into machine output;
		// expanded mode shows the full URL, otherwise the bare entity
		if r.Path != r.FullURL.String() {
			target = strings.TrimRight(r.Path, " ")
		}
	}

	rec := libgobuster.StableRecord{
		Key:          r.StableKey(),
		Target:       target,
		Location:     r.Header.Get("Location"),
		Chain:        r.Chain,
		StatusHidden: r.StatusHidden,
		SizeHidden:   r.SizeHidden,
	}
	if r.FullURL != nil {
		rec.Scheme = r.FullURL.Scheme
		rec.Host = r.FullURL.Host
	}
	if !r.StatusHidden {
		rec.Statuses = []int{r.StatusCode}
	}
	if !r.SizeHidden {
		rec.Sizes = []int64{r.Size}
	}
	return rec
}
