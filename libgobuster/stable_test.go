package libgobuster

import (
	"bytes"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestCanonicalHTTPKey(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "lowercases scheme and host, keeps path case",
			raw:  "HTTP://Example.COM/Path",
			want: "http://example.com/Path",
		},
		{
			name: "strips trailing slash except root",
			raw:  "http://example.com/admin/",
			want: "http://example.com/admin",
		},
		{
			name: "root keeps its slash",
			raw:  "http://example.com/",
			want: "http://example.com/",
		},
		{
			name: "sorted query parameters",
			raw:  "http://example.com/p?b=2&a=1",
			want: "http://example.com/p?a=1&b=2",
		},
		{
			name: "same path different host stays distinct",
			raw:  "http://other.example.com/p",
			want: "http://other.example.com/p",
		},
		{
			name: "same path different scheme stays distinct",
			raw:  "https://example.com/p",
			want: "https://example.com/p",
		},
	}

	for _, x := range tt {
		t.Run(x.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(x.raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := CanonicalHTTPKey(u); got != x.want {
				t.Fatalf("got %q want %q", got, x.want)
			}
		})
	}
}

func TestCanonicalHTTPKeyStableForTrailingSlashAndCase(t *testing.T) {
	t.Parallel()

	u1, _ := url.Parse("http://example.com/admin/")
	u2, _ := url.Parse("http://EXAMPLE.com/admin")
	if CanonicalHTTPKey(u1) != CanonicalHTTPKey(u2) {
		t.Fatal("trailing slash and host case variants must normalize to the same key")
	}
}

func TestCanonicalKeyNamespaced(t *testing.T) {
	t.Parallel()

	if CanonicalKey("dns", "a.example") == CanonicalKey("vhost", "a.example") {
		t.Fatal("different namespaces must not collide")
	}
}

func sampleRecord(key string, status int, size int64) StableRecord {
	return StableRecord{
		Key:      key,
		Target:   key,
		Statuses: []int{status},
		Sizes:    []int64{size},
	}
}

func TestStableRecordMergeAccumulatesMultiValues(t *testing.T) {
	t.Parallel()

	first := sampleRecord("k", 200, 10)
	first.Location = "/a"
	second := sampleRecord("k", 301, 20)
	second.Location = "/b"

	first.Merge(second)

	if len(first.Statuses) != 2 || first.Statuses[0] != 200 || first.Statuses[1] != 301 {
		t.Fatalf("statuses not merged as sorted multi value: %v", first.Statuses)
	}
	if len(first.Sizes) != 2 || first.Sizes[0] != 10 || first.Sizes[1] != 20 {
		t.Fatalf("sizes not merged as sorted multi value: %v", first.Sizes)
	}
	// first observation wins for scalar fields
	if first.Location != "/a" {
		t.Fatalf("representative location must be the first observation, got %q", first.Location)
	}
}

func TestStableRecordMergeDeduplicatesValues(t *testing.T) {
	t.Parallel()

	r := sampleRecord("k", 200, 10)
	r.Merge(sampleRecord("k", 200, 10))
	if len(r.Statuses) != 1 || len(r.Sizes) != 1 {
		t.Fatal("identical observations must collapse to one value")
	}
}

func TestHiddenDistinctFromZero(t *testing.T) {
	t.Parallel()

	hidden := StableRecord{Key: "k", Target: "k", StatusHidden: true, SizeHidden: true}
	zero := StableRecord{Key: "k", Target: "k", Statuses: []int{0}, Sizes: []int64{0}}

	var hb, zb bytes.Buffer
	if _, err := renderTSV(&hb, &sliceIterator{records: []StableRecord{hidden}}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := renderTSV(&zb, &sliceIterator{records: []StableRecord{zero}}, true); err != nil {
		t.Fatal(err)
	}
	if hb.String() == zb.String() {
		t.Fatal("hidden values must render differently from real zero values")
	}
	if !strings.Contains(hb.String(), HiddenValue) {
		t.Fatalf("hidden row must contain %q: %q", HiddenValue, hb.String())
	}
	if !strings.Contains(zb.String(), "0") {
		t.Fatalf("zero row must contain the real zero: %q", zb.String())
	}
}

func TestCompareStableRecordsIsTotalOrder(t *testing.T) {
	t.Parallel()

	a := sampleRecord("a", 200, 10)
	b := sampleRecord("b", 200, 10)
	if CompareStableRecords(a, b) >= 0 {
		t.Fatal("a must sort before b")
	}

	// same key, different status -> tie broken deterministically
	s1 := sampleRecord("k", 200, 10)
	s2 := sampleRecord("k", 404, 10)
	if CompareStableRecords(s1, s2) >= 0 {
		t.Fatal("status code must break the tie")
	}

	// identical content compares equal but remains a stable ordering
	if CompareStableRecords(s1, s1) != 0 {
		t.Fatal("identical records must compare equal")
	}
}

func TestAggregatorDeduplicatesAndSorts(t *testing.T) {
	t.Parallel()

	agg := NewAggregator(2) // tiny chunk size forces spilling
	inputs := []StableRecord{
		sampleRecord("http://example.com/c", 200, 5),
		sampleRecord("http://example.com/a", 200, 5),
		sampleRecord("http://example.com/b", 200, 5),
		sampleRecord("http://example.com/a", 301, 9), // duplicate key, new status
		sampleRecord("http://example.com/d", 200, 5),
	}
	for _, r := range inputs {
		if err := agg.Add(r); err != nil {
			t.Fatal(err)
		}
	}

	it, spilled, err := agg.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = it.Close() }()

	if spilled == 0 {
		t.Fatal("expected at least one spilled chunk with chunk size 2")
	}

	var keys []string
	var aRecord StableRecord
	for {
		r, ok := it.Next()
		if !ok {
			break
		}
		keys = append(keys, r.Key)
		if r.Key == "http://example.com/a" {
			aRecord = r
		}
	}

	want := []string{
		"http://example.com/a",
		"http://example.com/b",
		"http://example.com/c",
		"http://example.com/d",
	}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("got order %v want %v", keys, want)
	}
	if len(aRecord.Statuses) != 2 {
		t.Fatalf("duplicate key must merge across chunk boundaries, got %v", aRecord.Statuses)
	}
}

func TestRenderTSVFixedColumnsAndPlaceholders(t *testing.T) {
	t.Parallel()

	r := StableRecord{
		Key:      "http://example.com/a",
		Target:   "a",
		Scheme:   "http",
		Host:     "example.com",
		Statuses: []int{200, 301},
		Sizes:    []int64{0},
		Location: "",
		Extra:    "",
	}
	var buf bytes.Buffer
	n, err := renderTSV(&buf, &sliceIterator{records: []StableRecord{r}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("got %d records", n)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header + one row, got %q", buf.String())
	}
	header := strings.Split(lines[0], "\t")
	row := strings.Split(lines[1], "\t")
	if len(header) != len(row) || len(header) != len(tsvColumns) {
		t.Fatalf("column count mismatch: %d vs %d", len(header), len(tsvColumns))
	}
	if row[4] != "200,301" {
		t.Fatalf("multi value status field wrong: %q", row[4])
	}
	if row[5] != "0" {
		t.Fatalf("real zero length must render as 0 not the placeholder: %q", row[5])
	}
	if row[6] != EmptyValue || row[7] != EmptyValue || row[8] != EmptyValue {
		t.Fatalf("empty fields must use the unified placeholder: %q", lines[1])
	}
}

func TestRenderTSVEscapesSeparators(t *testing.T) {
	t.Parallel()

	r := StableRecord{Key: "k\ttab", Target: "line\nbreak\r"}
	var buf bytes.Buffer
	if _, err := renderTSV(&buf, &sliceIterator{records: []StableRecord{r}}, true); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("each record must occupy a single physical line, got %d lines", len(lines))
	}
	row := strings.Split(lines[1], "\t")
	if row[0] != "k tab" || row[1] != "line break " {
		t.Fatalf("tabs and newlines inside a field must be replaced with spaces: %q", lines[1])
	}
}

func TestRenderTextNoPaddingAndNoTrailingSpaces(t *testing.T) {
	t.Parallel()

	r := StableRecord{
		Key:      "http://example.com/short",
		Target:   "short",
		Statuses: []int{200},
		Sizes:    []int64{7},
	}
	var buf bytes.Buffer
	if _, err := renderText(&buf, &sliceIterator{records: []StableRecord{r}}, true); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	if strings.Contains(line, "  ") {
		t.Fatalf("stable text must not pad fields: %q", line)
	}
	for _, l := range strings.Split(strings.TrimRight(line, "\n"), "\n") {
		if l != strings.TrimRight(l, " ") {
			t.Fatalf("line must not end with trailing spaces: %q", l)
		}
	}
}

func TestEncodeChainMarksLoopAndTruncation(t *testing.T) {
	t.Parallel()

	chain := &RedirectChain{
		Hops: []RedirectHop{
			{Status: 301, Location: "/a", URL: "http://example.com/a"},
			{Status: 302, Location: "/b", URL: "http://example.com/b"},
		},
		FinalURL: "http://example.com/b",
		Loop:     true,
		CutOff:   true,
	}
	got := encodeChainText(chain)
	if !strings.Contains(got, "301->/a") || !strings.Contains(got, "302->/b") {
		t.Fatalf("chain hops missing: %q", got)
	}
	if !strings.Contains(got, "LOOP") || !strings.Contains(got, "TRUNCATED") {
		t.Fatalf("anomaly markers missing: %q", got)
	}
	if !strings.Contains(got, "final=http://example.com/b") {
		t.Fatalf("final landing missing: %q", got)
	}
}

func TestFileIteratorRemovesChunkOnClose(t *testing.T) {
	t.Parallel()

	agg := NewAggregator(1)
	if err := agg.Add(sampleRecord("http://example.com/a", 200, 1)); err != nil {
		t.Fatal(err)
	}
	if err := agg.Add(sampleRecord("http://example.com/b", 200, 1)); err != nil {
		t.Fatal(err)
	}
	it, _, err := agg.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, ok := it.Next(); !ok {
			break
		}
	}
	if err := it.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range agg.spilled {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("chunk file %s was not removed", name)
		}
	}
}
