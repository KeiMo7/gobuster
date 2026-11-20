package gobusterdir

import (
	"github.com/OJ/gobuster/v3/libgobuster"
)

// OptionsDir is the struct to hold all options for this plugin
type OptionsDir struct {
	libgobuster.HTTPOptions
	Extensions                 string
	ExtensionsParsed           libgobuster.Set[string]
	ExtensionsFile             string
	StatusCodes                string
	StatusCodesParsed          libgobuster.Set[int]
	StatusCodesBlacklist       string
	StatusCodesBlacklistParsed libgobuster.Set[int]
	UseSlash                   bool
	HideLength                 bool
	Expanded                   bool
	NoStatus                   bool
	DiscoverBackup             bool
	ExcludeLength              string
	ExcludeLengthParsed        libgobuster.Set[int]
	Force                      bool

	// Recursion is enabled and bounded through the global options. These
	// fields define which discovered directories may be expanded and which are
	// excluded. All rules are evaluated before a directory is queued.
	RecursionExcludePaths   []string
	RecursionExcludeStatus  string
	RecursionExcludeStatusP libgobuster.Set[int]
	RecursionExcludeLength  string
	RecursionExcludeLenP    libgobuster.Set[int]
	RecursionExpandOnly     []string
}

// NewOptions returns a new initialized OptionsDir
func NewOptions() *OptionsDir {
	return &OptionsDir{
		StatusCodesParsed:          libgobuster.NewSet[int](),
		StatusCodesBlacklistParsed: libgobuster.NewSet[int](),
		ExtensionsParsed:           libgobuster.NewSet[string](),
		ExcludeLengthParsed:        libgobuster.NewSet[int](),
		RecursionExcludeStatusP:    libgobuster.NewSet[int](),
		RecursionExcludeLenP:       libgobuster.NewSet[int](),
	}
}
