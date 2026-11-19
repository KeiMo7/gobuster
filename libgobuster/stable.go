package libgobuster

import (
	"bytes"
	"container/heap"
	"encoding/gob"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Output format names accepted by Options.OutputFormat.
const (
	OutputFormatText = "text"
	OutputFormatTSV  = "tsv"
)

// placeholders used by the machine parseable output
const (
	// EmptyValue marks a field that is genuinely empty.
	EmptyValue = "-"
	// HiddenValue marks a field that exists but was deliberately hidden
	// (e.g. via --no-status or --hide-length). It must never be confused
	// with a real zero value.
	HiddenValue = "*"
)

// RedirectChain captures the redirect hops observed for a single request.
type RedirectChain struct {
	// Hops holds every hop from the first redirect up to the final one.
	Hops []RedirectHop
	// FinalURL is the URL of the last response.
	FinalURL string
	// Loop is true when the chain revisited an already seen URL.
	Loop bool
	// CutOff is true when the chain was truncated at MaxRedirectHops.
	CutOff bool
}

// StableRecord is the normalized, mode independent representation of a result
// used by the stable output pipeline.
type StableRecord struct {
	// Key is the deduplication key built from the normalized target identity.
	Key string
	// Target is the human readable identity as printed (path, vhost, ...).
	Target string
	// Scheme and Host are kept separately so different hosts or protocols
	// sharing a path never collapse into one record.
	Scheme string
	Host   string
	// Statuses holds every distinct status code observed for the key.
	Statuses []int
	// StatusHidden is true when the status was hidden by configuration.
	StatusHidden bool
	// Sizes holds every distinct response length observed for the key.
	Sizes []int64
	// SizeHidden is true when the length was hidden by configuration.
	SizeHidden bool
	// Location is the last redirect location header seen (may be empty).
	Location string
	// Chain is the optional redirect chain.
	Chain *RedirectChain
	// Extra holds mode specific additional single line information.
	Extra string
}

// NormalizedResult is implemented by plugin results that participate in the
// stable, deduplicated output pipeline.
type NormalizedResult interface {
	Result
	// StableKey returns the deduplication key of the normalized target.
	StableKey() string
	// StableRecord converts the plugin result into the common record type.
	StableRecord() StableRecord
}

// CanonicalHTTPKey builds the deterministic identity of an HTTP target.
// The key always contains scheme, host, path and query so the same path on
// different hosts or protocols can never be merged.
// Trailing slashes (except the root) are stripped and scheme/host are
// lowercased; the path itself stays case sensitive. Query parameters are
// sorted by key while their value order is preserved.
func CanonicalHTTPKey(u *url.URL) string {
	if u == nil {
		return ""
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
		if path == "" {
			path = "/"
		}
	}

	query := canonicalQuery(u)

	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	b.WriteString(path)
	if query != "" {
		b.WriteByte('?')
		b.WriteString(query)
	}
	return b.String()
}

// CanonicalKey builds a namespaced identity for non HTTP targets. The namespace
// (plugin name) prevents identical words from different modes from colliding.
func CanonicalKey(namespace, target string) string {
	return namespace + "://" + target
}

func canonicalQuery(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		// an unparseable query is rendered verbatim instead of dropping data
		return u.RawQuery
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		for _, v := range values[k] {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// Merge folds another observation of the same key into the receiver.
// Scalar fields follow an explainable rule: the first observation wins, only
// multi valued fields (status codes, lengths, chain) are accumulated.
func (r *StableRecord) Merge(other StableRecord) {
	r.Statuses = mergeSortedInts(r.Statuses, other.Statuses)
	r.Sizes = mergeSortedInt64s(r.Sizes, other.Sizes)
	r.StatusHidden = r.StatusHidden || other.StatusHidden
	r.SizeHidden = r.SizeHidden || other.SizeHidden
	if r.Location == "" && other.Location != "" {
		r.Location = other.Location
	}
	if r.Chain == nil && other.Chain != nil {
		// keep the first observed chain; a chain only describes the request
		// that carried it and merging chains would imply a non existent order
		r.Chain = other.Chain
	}
	if r.Extra == "" && other.Extra != "" {
		r.Extra = other.Extra
	}
}

func mergeSortedInts(a, b []int) []int {
	seen := make(map[int]struct{}, len(a)+len(b))
	out := make([]int, 0, len(a)+len(b))
	for _, v := range append(append([]int{}, a...), b...) {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func mergeSortedInt64s(a, b []int64) []int64 {
	seen := make(map[int64]struct{}, len(a)+len(b))
	out := make([]int64, 0, len(a)+len(b))
	for _, v := range append(append([]int64{}, a...), b...) {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CompareStableRecords defines the total order of the terminal output.
// It returns -1, 0 or 1 and never reports equality for distinct records
// because every field participates in the comparison.
func CompareStableRecords(a, b StableRecord) int {
	if c := strings.Compare(a.Key, b.Key); c != 0 {
		return c
	}
	if c := compareIntSlice(a.Statuses, b.Statuses); c != 0 {
		return c
	}
	if c := compareInt64Slice(a.Sizes, b.Sizes); c != 0 {
		return c
	}
	if c := strings.Compare(a.Target, b.Target); c != 0 {
		return c
	}
	if c := strings.Compare(a.Location, b.Location); c != 0 {
		return c
	}
	if c := strings.Compare(a.Scheme, b.Scheme); c != 0 {
		return c
	}
	if c := strings.Compare(a.Host, b.Host); c != 0 {
		return c
	}
	if c := strings.Compare(chainOrderKey(a.Chain), chainOrderKey(b.Chain)); c != 0 {
		return c
	}
	return strings.Compare(a.Extra, b.Extra)
}

func chainOrderKey(c *RedirectChain) string {
	if c == nil {
		return ""
	}
	parts := make([]string, 0, len(c.Hops)+1)
	for _, h := range c.Hops {
		parts = append(parts, fmt.Sprintf("%d:%s", h.Status, h.URL))
	}
	parts = append(parts, c.FinalURL)
	return strings.Join(parts, "|")
}

func compareIntSlice(a, b []int) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := range n {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

func compareInt64Slice(a, b []int64) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := range n {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// recordIterator streams sorted, not yet deduplicated records.
type recordIterator interface {
	Next() (StableRecord, bool)
	Close() error
}

// sliceIterator iterates an in memory sorted slice.
type sliceIterator struct {
	records []StableRecord
	pos     int
}

func (s *sliceIterator) Next() (StableRecord, bool) {
	if s.pos >= len(s.records) {
		return StableRecord{}, false
	}
	r := s.records[s.pos]
	s.pos++
	return r, true
}

func (s *sliceIterator) Close() error { return nil }

// fileIterator streams a gob encoded sorted chunk from disk.
type fileIterator struct {
	f      *os.File
	dec    *gob.Decoder
	closed bool
}

func (f *fileIterator) Next() (StableRecord, bool) {
	var r StableRecord
	if err := f.dec.Decode(&r); err != nil {
		_ = f.Close()
		return StableRecord{}, false
	}
	return r, true
}

func (f *fileIterator) Close() error {
	if f.closed {
		return nil
	}
	f.closed = true
	name := f.f.Name()
	err := f.f.Close()
	if rmErr := os.Remove(name); rmErr != nil && err == nil {
		err = rmErr
	}
	return err
}

// mergeHeap implements heap.Interface over iterators keyed by their head record.
type mergeHeap struct {
	heads []StableRecord
	iters []recordIterator
}

func (h *mergeHeap) Len() int { return len(h.heads) }
func (h *mergeHeap) Less(i, j int) bool {
	return CompareStableRecords(h.heads[i], h.heads[j]) < 0
}
func (h *mergeHeap) Swap(i, j int) {
	h.heads[i], h.heads[j] = h.heads[j], h.heads[i]
	h.iters[i], h.iters[j] = h.iters[j], h.iters[i]
}
func (h *mergeHeap) Push(_ any) { panic("use heapPush") }
func (h *mergeHeap) Pop() any   { panic("use heapPop") }

func heapPush(h *mergeHeap, r StableRecord, it recordIterator) {
	h.heads = append(h.heads, r)
	h.iters = append(h.iters, it)
	heap.Fix(h, len(h.heads)-1)
}

func heapPop(h *mergeHeap) (StableRecord, recordIterator) {
	n := len(h.heads) - 1
	h.Swap(0, n)
	r := h.heads[n]
	it := h.iters[n]
	h.heads = h.heads[:n]
	h.iters = h.iters[:n]
	if n > 0 {
		heap.Fix(h, 0)
	}
	return r, it
}

// Aggregator collects observations, deduplicates by normalized key and emits
// the terminal output in a deterministic total order. Above the configured
// chunk size sorted chunks are spilled to disk and merged externally so the
// memory peak stays bounded.
type Aggregator struct {
	chunkSize int
	buf       map[string]*StableRecord
	order     []string
	spilled   []string
}

// NewAggregator creates an Aggregator. chunkSize <= 0 falls back to the
// package default.
func NewAggregator(chunkSize int) *Aggregator {
	if chunkSize <= 0 {
		chunkSize = DefaultStableChunkSize
	}
	return &Aggregator{
		chunkSize: chunkSize,
		buf:       make(map[string]*StableRecord),
	}
}

// Add stores one observation. Duplicate keys are merged on the fly.
func (a *Aggregator) Add(r StableRecord) error {
	if existing, ok := a.buf[r.Key]; ok {
		existing.Merge(r)
		return nil
	}
	cp := r
	a.buf[r.Key] = &cp
	a.order = append(a.order, r.Key)

	if len(a.buf) >= a.chunkSize {
		return a.spill()
	}
	return nil
}

func (a *Aggregator) spill() error {
	records := make([]StableRecord, 0, len(a.order))
	for _, k := range a.order {
		records = append(records, *a.buf[k])
	}
	sort.Slice(records, func(i, j int) bool {
		return CompareStableRecords(records[i], records[j]) < 0
	})

	f, err := os.CreateTemp("", "gobuster-stable-*.chunk")
	if err != nil {
		return fmt.Errorf("could not create stable output chunk: %w", err)
	}
	enc := gob.NewEncoder(f)
	for i := range records {
		if err := enc.Encode(&records[i]); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return fmt.Errorf("could not write stable output chunk: %w", err)
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return fmt.Errorf("could not sync stable output chunk: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return fmt.Errorf("could not close stable output chunk: %w", err)
	}
	a.spilled = append(a.spilled, f.Name())

	a.buf = make(map[string]*StableRecord)
	a.order = a.order[:0]
	return nil
}

// Finalize sorts and deduplicates everything and returns a streaming
// iterator. The caller must close it so chunk files are removed.
func (a *Aggregator) Finalize() (recordIterator, int, error) {
	iters := make([]recordIterator, 0, len(a.spilled)+1)
	for _, name := range a.spilled {
		f, err := os.Open(name)
		if err != nil {
			// release every chunk already opened before failing
			for _, it := range iters {
				_ = it.Close()
			}
			return nil, 0, fmt.Errorf("could not open stable output chunk: %w", err)
		}
		iters = append(iters, &fileIterator{f: f, dec: gob.NewDecoder(f)})
	}

	memoryRecords := make([]StableRecord, 0, len(a.order))
	for _, k := range a.order {
		memoryRecords = append(memoryRecords, *a.buf[k])
	}
	sort.Slice(memoryRecords, func(i, j int) bool {
		return CompareStableRecords(memoryRecords[i], memoryRecords[j]) < 0
	})
	iters = append(iters, &sliceIterator{records: memoryRecords})

	mh := &mergeHeap{
		heads: make([]StableRecord, 0, len(iters)),
		iters: make([]recordIterator, 0, len(iters)),
	}
	for _, it := range iters {
		if r, ok := it.Next(); ok {
			heapPush(mh, r, it)
		} else {
			_ = it.Close()
		}
	}

	return &dedupIterator{heap: mh}, len(a.spilled), nil
}

// dedupIterator performs the k-way merge and the global deduplication.
type dedupIterator struct {
	heap    *mergeHeap
	started bool
	current StableRecord
}

func (d *dedupIterator) Next() (StableRecord, bool) {
	for d.heap.Len() > 0 {
		r, it := heapPop(d.heap)
		if next, ok := it.Next(); ok {
			heapPush(d.heap, next, it)
		} else {
			_ = it.Close()
		}

		if !d.started {
			d.started = true
			d.current = r
			continue
		}
		if d.current.Key == r.Key {
			// same normalized identity arriving from another chunk: fold it
			// in and keep draining until a strictly larger key shows up
			d.current.Merge(r)
			continue
		}
		// a strictly larger key means the previous record is fully merged
		out := d.current
		d.current = r
		return out, true
	}
	if !d.started {
		return StableRecord{}, false
	}
	out := d.current
	d.started = false
	return out, true
}

func (d *dedupIterator) Close() error {
	var firstErr error
	for d.heap.Len() > 0 {
		_, it := heapPop(d.heap)
		if err := it.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// RenderStable writes the fully ordered, deduplicated records to w in the
// requested format and returns the number of records written.
// It never emits terminal control characters so stdout and file output are
// byte identical for the same input.
func RenderStable(w io.Writer, it recordIterator, format string, includeChain bool) (int, error) {
	switch format {
	case "", OutputFormatText:
		return renderText(w, it, includeChain)
	case OutputFormatTSV:
		return renderTSV(w, it, includeChain)
	default:
		return 0, fmt.Errorf("unknown stable output format %q", format)
	}
}

func renderText(w io.Writer, it recordIterator, includeChain bool) (int, error) {
	var b bytes.Buffer
	count := 0
	for {
		r, ok := it.Next()
		if !ok {
			break
		}
		b.Reset()
		b.WriteString(r.Target)

		if r.StatusHidden {
			fmt.Fprintf(&b, " (Status: %s)", HiddenValue)
		} else if len(r.Statuses) > 0 {
			fmt.Fprintf(&b, " (Status: %s)", joinInts(r.Statuses))
		}

		if r.SizeHidden {
			fmt.Fprintf(&b, " [Size: %s]", HiddenValue)
		} else if len(r.Sizes) > 0 {
			fmt.Fprintf(&b, " [Size: %s]", joinInt64s(r.Sizes))
		}

		if r.Location != "" {
			fmt.Fprintf(&b, " [--> %s]", r.Location)
		}

		if includeChain {
			if chain := encodeChainText(r.Chain); chain != "" {
				fmt.Fprintf(&b, " [Chain: %s]", chain)
			}
		}

		if r.Extra != "" {
			fmt.Fprintf(&b, " [%s]", r.Extra)
		}

		if _, err := fmt.Fprintf(w, "%s\n", strings.TrimRight(b.String(), " ")); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// tsvColumns documents the fixed column layout of the machine output.
var tsvColumns = []string{
	"key", "target", "scheme", "host", "statuses", "sizes",
	"location", "chain", "extra",
}

func renderTSV(w io.Writer, it recordIterator, includeChain bool) (int, error) {
	header := strings.Join(tsvColumns, "\t")
	if _, err := fmt.Fprintln(w, header); err != nil {
		return 0, err
	}

	count := 0
	for {
		r, ok := it.Next()
		if !ok {
			break
		}

		statuses := EmptyValue
		if r.StatusHidden {
			statuses = HiddenValue
		} else if len(r.Statuses) > 0 {
			statuses = joinInts(r.Statuses)
		}

		sizes := EmptyValue
		if r.SizeHidden {
			sizes = HiddenValue
		} else if len(r.Sizes) > 0 {
			sizes = joinInt64s(r.Sizes)
		}

		location := r.Location
		if location == "" {
			location = EmptyValue
		}

		chain := EmptyValue
		if includeChain {
			if c := encodeChainText(r.Chain); c != "" {
				chain = c
			}
		}

		extra := r.Extra
		if extra == "" {
			extra = EmptyValue
		}

		fields := []string{
			tsvEscape(r.Key),
			tsvEscape(r.Target),
			tsvEscape(orDash(r.Scheme)),
			tsvEscape(orDash(r.Host)),
			statuses,
			sizes,
			tsvEscape(location),
			tsvEscape(chain),
			tsvEscape(extra),
		}
		if _, err := fmt.Fprintln(w, strings.Join(fields, "\t")); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func orDash(s string) string {
	if s == "" {
		return EmptyValue
	}
	return s
}

// tsvEscape guarantees a single physical line per record and fixed tabs as
// the only field delimiter.
func tsvEscape(s string) string {
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

func encodeChainText(c *RedirectChain) string {
	if c == nil || len(c.Hops) == 0 {
		return ""
	}
	parts := make([]string, 0, len(c.Hops)+1)
	for _, h := range c.Hops {
		target := h.Location
		if target == "" {
			target = h.URL
		}
		parts = append(parts, fmt.Sprintf("%d->%s", h.Status, target))
	}
	parts = append(parts, "final="+c.FinalURL)
	if c.Loop {
		parts = append(parts, "LOOP")
	}
	if c.CutOff {
		parts = append(parts, "TRUNCATED")
	}
	return strings.Join(parts, " ")
}

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, ",")
}

func joinInt64s(v []int64) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, ",")
}

// StatsReport holds the fixed counters rendered at the end of a run. The
// semantics are identical for every output mode.
type StatsReport struct {
	RequestsTotal    int
	UniqueResults    int
	FilteredStatus   int
	FilteredLength   int
	FilteredWildcard int
	Errors           int
	SpilledChunks    int
}

// RenderStats prints the fixed statistics block to w. It is meant for the
// log channel (stderr) so it never mixes with the result stream.
func RenderStats(w io.Writer, s StatsReport) error {
	lines := []string{
		"===============================================================",
		fmt.Sprintf("Requests total:      %d", s.RequestsTotal),
		fmt.Sprintf("Unique results:      %d", s.UniqueResults),
		fmt.Sprintf("Filtered (status):   %d", s.FilteredStatus),
		fmt.Sprintf("Filtered (length):   %d", s.FilteredLength),
		fmt.Sprintf("Filtered (wildcard): %d", s.FilteredWildcard),
		fmt.Sprintf("Errors:              %d", s.Errors),
		fmt.Sprintf("Spilled chunks:      %d", s.SpilledChunks),
		"===============================================================",
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}
