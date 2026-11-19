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

// StableKey returns the normalized target identity used for deduplication.
func (r Result) StableKey() string {
	return libgobuster.CanonicalKey("s3", r.BucketName)
}

// StableRecord converts the result to the mode independent stable record.
func (r Result) StableRecord() libgobuster.StableRecord {
	target := "http://" + r.BucketName + ".s3.amazonaws.com/"
	rec := libgobuster.StableRecord{
		Key:    r.StableKey(),
		Target: target,
		Scheme: "http",
		Host:   r.BucketName + ".s3.amazonaws.com",
	}
	if r.Status != "" {
		rec.Extra = r.Status
	}
	return rec
}
