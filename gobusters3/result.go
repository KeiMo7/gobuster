package gobusters3

import (
	"bytes"

	"github.com/OJ/gobuster/v3/libgobuster"
	"github.com/fatih/color"
)

var green = color.New(color.FgGreen).FprintfFunc()

// Result represents a single result
type Result struct {
	Found      bool
	BucketName string
	Status     string
}

// ResultToString converts the Result to its textual representation
func (r Result) ResultToString() (string, error) {
	buf := &bytes.Buffer{}

	c := green

	c(buf, "http://%s.s3.amazonaws.com/", r.BucketName)

	if r.Status != "" {
		c(buf, " [%s]", r.Status)
	}
	c(buf, "\n")

	str := buf.String()
	return str, nil
}

// ToSARIF converts the result into stable SARIF data.
func (r Result) ToSARIF() libgobuster.SARIFFinding {
	properties := map[string]string{"bucket": r.BucketName}
	if r.Status != "" {
		properties["status"] = r.Status
	}
	return libgobuster.SARIFFinding{
		RuleID:          libgobuster.SARIFS3BucketRuleID,
		Message:         "S3 bucket discovered: " + r.BucketName,
		LogicalLocation: r.BucketName,
		Properties:      properties,
	}
}
