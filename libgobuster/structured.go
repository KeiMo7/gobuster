package libgobuster

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// StructuredResult is the fixed schema of one JSONL record. The field order
// of this struct defines the key order in the emitted JSON and must not be
// changed, downstream parsers rely on it.
//
// Field semantics:
//   - timestamp:   time the hit was observed, RFC3339 with nanoseconds
//   - plugin:      name of the plugin that produced the hit
//   - target:      base target of the scan (e.g. https://example.com/)
//   - path:        the matched path / word / subdomain / bucket
//   - status_code: HTTP status code, -1 if not applicable for the plugin
//   - length:      response body length in bytes, -1 if not applicable
//   - redirect:    value of the Location header, "" if none
//   - duration_ms: wall time of the request in milliseconds
//   - is_new:      true if this exact hit was not present in the output
//     file before this run (see StructuredWriter)
type StructuredResult struct {
	Timestamp  string `json:"timestamp"`
	Plugin     string `json:"plugin"`
	Target     string `json:"target"`
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Length     int64  `json:"length"`
	Redirect   string `json:"redirect"`
	DurationMs int64  `json:"duration_ms"`
	IsNew      bool   `json:"is_new"`
}

// StructuredFields are the plugin specific parts of a StructuredResult
type StructuredFields struct {
	Target     string
	Path       string
	StatusCode int
	Length     int64
	Redirect   string
}

// ResultFieldsProvider is an optional interface a plugin Result can
// implement to be included in the structured output
type ResultFieldsProvider interface {
	ResultFields() StructuredFields
}

// dedupeKey is the identity of a hit used for the is_new classification
func (r StructuredResult) dedupeKey() string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%d", r.Plugin, r.Target, r.Path, r.StatusCode)
}

// StructuredWriter appends results as JSON lines to a file. The file is
// opened with O_APPEND so concurrent gobuster processes never overwrite
// each other; every record is emitted with a single Write call so lines
// from different processes never interleave. Within the process a mutex
// serializes writers.
type StructuredWriter struct {
	mu    sync.Mutex
	f     *os.File
	known map[string]struct{}
}

// NewStructuredWriter opens (creating if needed) the JSONL file for
// appending and loads all previously recorded hits so the is_new flag can
// be computed for subsequent runs.
func NewStructuredWriter(filename string) (*StructuredWriter, error) {
	w := &StructuredWriter{known: make(map[string]struct{})}

	// load historical hits for the is_new classification; a missing file
	// is fine, a corrupted line is skipped (it might come from another tool)
	if existing, err := os.Open(filename); err == nil {
		defer existing.Close()
		scanner := bufio.NewScanner(existing)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var r StructuredResult
			if err := json.Unmarshal(line, &r); err != nil {
				continue
			}
			w.known[r.dedupeKey()] = struct{}{}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read existing structured output file %q: %w", filename, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to open structured output file %q: %w", filename, err)
	}

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open structured output file %q: %w", filename, err)
	}
	w.f = f
	return w, nil
}

// Write classifies the record (is_new), serializes it and appends it with a
// single write call. A record is only counted as known after it has been
// written successfully, so a failed write never marks a hit as historical.
func (w *StructuredWriter) Write(r StructuredResult) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	key := r.dedupeKey()
	_, seen := w.known[key]
	r.IsNew = !seen

	buf, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed to marshal structured result: %w", err)
	}
	buf = append(buf, '\n')
	if _, err := w.f.Write(buf); err != nil {
		return fmt.Errorf("failed to write structured result: %w", err)
	}
	w.known[key] = struct{}{}
	return nil
}

// Close closes the underlying file
func (w *StructuredWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}
