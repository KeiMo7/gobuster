package libgobuster

import "context"

// GobusterPlugin is an interface which plugins must implement
type GobusterPlugin interface {
	Name() string
	PreRun(context.Context, *Progress) error
	ProcessWord(context.Context, string, *Progress) (Result, error)
	AdditionalWords(string) []string
	AdditionalWordsLen() int
	AdditionalSuccessWords(string) []string
	GetConfigString() (string, error)
}

// Result is an interface for the Result object
type Result interface {
	ResultToString() (string, error)
}

// RecursiveResult is implemented by results which can seed another scan.
// An empty target means that the result must not be recursed into.
type RecursiveResult interface {
	Result
	RecursiveTarget() string
}

// SuppressedResult is implemented by results which should seed another scan
// (or be counted) without being written to the normal result output.
type SuppressedResult interface {
	Result
	SuppressResult() bool
}

// RecursivePlugin is implemented by plugins which support recursive scans.
// SetTarget is only called after the previous scan has fully stopped, so
// implementations do not need to synchronize target access.
type RecursivePlugin interface {
	GobusterPlugin
	SetTarget(string) error
	// RootTarget returns the base URL of the initial scan. It is used to
	// seed the visited-directory set and to reject cross-origin targets.
	RootTarget() string
}
