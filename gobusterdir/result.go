package gobusterdir

import (
	"bytes"
	"fmt"
	"net/http"
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

// ToSARIF converts the result into stable SARIF data.
func (r Result) ToSARIF() libgobuster.SARIFFinding {
	path := strings.TrimSpace(r.Path)
	ruleID := libgobuster.SARIFRuleForStatus(r.StatusCode)
	properties := map[string]string{}
	if r.StatusCode >= 0 {
		properties["statusCode"] = fmt.Sprintf("%d", r.StatusCode)
	}
	if r.Size >= 0 {
		properties["size"] = fmt.Sprintf("%d", r.Size)
	}
	if location := r.Header.Get("Location"); location != "" {
		properties["location"] = location
	}

	message := fmt.Sprintf("HTTP resource discovered: %s", path)
	switch ruleID {
	case libgobuster.SARIFHTTPRedirectRuleID:
		message = fmt.Sprintf("HTTP redirect discovered: %s", path)
	case libgobuster.SARIFHTTPAccessRuleID:
		message = fmt.Sprintf("Access-controlled HTTP resource discovered: %s", path)
	case libgobuster.SARIFHTTPServerErrorRuleID:
		message = fmt.Sprintf("HTTP server error discovered: %s", path)
	case libgobuster.SARIFHTTPSuccessRuleID:
		message = fmt.Sprintf("HTTP resource discovered: %s", path)
	case libgobuster.SARIFHTTPOtherRuleID:
		message = fmt.Sprintf("HTTP response discovered: %s", path)
	}
	if r.StatusCode >= 0 {
		message = fmt.Sprintf("%s (status %d)", message, r.StatusCode)
	}
	if r.Size >= 0 {
		message = fmt.Sprintf("%s (size %d)", message, r.Size)
	}

	return libgobuster.SARIFFinding{
		RuleID:          ruleID,
		Message:         message,
		LogicalLocation: path,
		Properties:      properties,
	}
}
