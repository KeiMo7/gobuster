package libgobuster

import (
	"fmt"
	"time"
)

// Options holds all options that can be passed to libgobuster
type Options struct {
	Threads             int
	Debug               bool
	Wordlist            string
	WordlistOffset      int
	PatternFile         string
	DiscoverPatternFile string
	Patterns            []string
	DiscoverPatterns    []string
	OutputFilename      string
	NoProgress          bool
	NoError             bool
	Quiet               bool
	Delay               time.Duration
	// Recursion enables expanding discovered directories with the same wordlist.
	Recursion bool
	// RecursionDepth is the maximum directory level to expand. The initial
	// base URL is level 0, so a value of 0 means no expansion at all.
	RecursionDepth int
	// RecursionMaxTargets bounds the number of unique directories kept in
	// memory. 0 means unlimited.
	RecursionMaxTargets int
}

// ValidateRecursionLimits rejects recursion limits that cannot produce a
// consistent run. It is called at startup, before any request is issued.
func (o *Options) ValidateRecursionLimits() error {
	if o.RecursionDepth < 0 {
		return fmt.Errorf("recursion-depth must be greater than or equal to 0, got %d", o.RecursionDepth)
	}
	if o.RecursionMaxTargets < 0 {
		return fmt.Errorf("recursion-max-targets must be greater than or equal to 0, got %d", o.RecursionMaxTargets)
	}
	return nil
}
