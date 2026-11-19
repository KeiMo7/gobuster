package libgobuster

import (
	"time"
)

// DefaultStableChunkSize is the number of unique results kept in memory before
// a sorted chunk is spilled to disk during external merge sort.
const DefaultStableChunkSize = 50000

// MaxRedirectHops is the maximum number of redirect hops that are recorded
// before the chain is marked as truncated. It matches the net/http default.
const MaxRedirectHops = 10

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
	// Stable enables deterministic, deduplicated and sorted terminal output.
	// When disabled the legacy streaming behaviour is kept byte for byte.
	Stable bool
	// OutputFormat selects the rendering of the stable output.
	// Empty and "text" render the human readable line format, "tsv" renders
	// machine parseable tab separated values.
	OutputFormat string
	// NoChain disables the redirect chain field in stable output.
	NoChain bool
	// StableChunkSize is the in-memory chunk size used by the external merge
	// sort. Zero means DefaultStableChunkSize.
	StableChunkSize int
}
