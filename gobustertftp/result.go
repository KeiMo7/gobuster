package gobustertftp

import (
	"bytes"
	"fmt"

	"github.com/OJ/gobuster/v3/libgobuster"
	"github.com/fatih/color"
)

var green = color.New(color.FgGreen).FprintfFunc()

// Result represents a single result
type Result struct {
	Filename     string
	Size         int64
	ErrorMessage string
}

// ResultToString converts the Result to its textual representation
func (r Result) ResultToString() (string, error) {
	buf := &bytes.Buffer{}

	green(buf, "%s", r.Filename)
	if r.Size > 0 {
		if _, err := fmt.Fprintf(buf, " [%d]", r.Size); err != nil {
			return "", err
		}
	}

	if _, err := fmt.Fprintf(buf, "\n"); err != nil {
		return "", err
	}

	s := buf.String()
	return s, nil
}

// StableKey returns the normalized target identity used for deduplication.
func (r Result) StableKey() string {
	return libgobuster.CanonicalKey("tftp", r.Filename)
}

// StableRecord converts the result to the mode independent stable record.
func (r Result) StableRecord() libgobuster.StableRecord {
	rec := libgobuster.StableRecord{
		Key:    r.StableKey(),
		Target: r.Filename,
	}
	// a real length of zero is rendered as 0; a missing size stays empty
	if r.Size > 0 {
		rec.Sizes = []int64{r.Size}
	}
	if r.ErrorMessage != "" {
		rec.Extra = "Error=" + r.ErrorMessage
	}
	return rec
}
