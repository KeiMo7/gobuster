package libgobuster

import (
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
	// OutputStructuredFilename is the path of the JSONL structured output
	// file. Empty disables structured output.
	OutputStructuredFilename string
	// RateLimit is the global requests per second limit, 0 disables it
	RateLimit float64
	// RateLimitPerTarget is the per-target requests per second limit, 0 disables it
	RateLimitPerTarget float64
	// RateControlFile is a JSON file watched at runtime for rate changes
	RateControlFile string
	// RateAdaptive enables AIMD auto-tuning on throttling responses
	RateAdaptive bool
	// RateMin is the lower bound for adaptive rate decreases
	RateMin float64
	// RateLimiter is the runtime limiter group built from the options above
	RateLimiter *RateLimitGroup
}
