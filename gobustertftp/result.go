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

// ToSARIF converts the result into stable SARIF data.
func (r Result) ToSARIF() libgobuster.SARIFFinding {
	properties := map[string]string{}
	if r.Size > 0 {
		properties["size"] = fmt.Sprintf("%d", r.Size)
	}
	if r.ErrorMessage != "" {
		properties["error"] = r.ErrorMessage
	}

	return libgobuster.SARIFFinding{
		RuleID:          libgobuster.SARIFTFTPSuccessRuleID,
		Message:         fmt.Sprintf("TFTP file discovered: %s", r.Filename),
		LogicalLocation: r.Filename,
		Properties:      properties,
	}
}
