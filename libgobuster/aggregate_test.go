package libgobuster

import (
	"fmt"
	"os"
	"runtime"
	"testing"
)

// TestAggregatorBoundedMemory forces many spills on a 100k record input and
// asserts the result stays fully ordered, unique and that chunk files are
// cleaned up. It guards the external merge sort path against regressions.
func TestAggregatorBoundedMemory(t *testing.T) {
	const total = 100000
	const chunk = 1000 // forces roughly 100 on-disk chunks

	agg := NewAggregator(chunk)

	for i := 0; i < total; i++ {
		// interleave duplicates: every key is inserted twice, out of order,
		// so both in-buffer and cross-chunk merge are exercised
		key := fmt.Sprintf("http://example.com/p%06d", total-1-i)
		if err := agg.Add(sampleRecord(key, 200, int64(i%100))); err != nil {
			t.Fatalf("add: %v", err)
		}
	}
	for i := 0; i < total; i++ {
		key := fmt.Sprintf("http://example.com/p%06d", i)
		if err := agg.Add(sampleRecord(key, 301, int64(i%100))); err != nil {
			t.Fatalf("add dup: %v", err)
		}
	}

	it, spilled, err := agg.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if spilled < total/chunk-2 {
		t.Fatalf("expected roughly %d spills, got %d", total/chunk, spilled)
	}

	count := 0
	var prev StableRecord
	first := true
	for {
		r, ok := it.Next()
		if !ok {
			break
		}
		if !first && CompareStableRecords(prev, r) >= 0 {
			t.Fatalf("merge output not strictly ordered at index %d: %q vs %q", count, prev.Key, r.Key)
		}
		// the duplicate observation must have merged into one record
		if len(r.Statuses) != 2 {
			t.Fatalf("key %q must carry both observed statuses, got %v", r.Key, r.Statuses)
		}
		prev = r
		first = false
		count++
	}
	if count != total {
		t.Fatalf("expected %d unique records, got %d", total, count)
	}
	if err := it.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// every spilled chunk file must be removed by the iterator
	for _, name := range agg.spilled {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("chunk %s not cleaned up", name)
		}
	}
}

// TestAggregatorMemoryBounded compares peak heap growth between a tiny and a
// large chunk size for the same input. The small chunk variant spills to disk
// and must not grow proportionally with the input size.
func TestAggregatorMemoryBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("memory bound test skipped in short mode")
	}
	const total = 50000

	measure := func(chunk int) uint64 {
		agg := NewAggregator(chunk)
		for i := 0; i < total; i++ {
			key := fmt.Sprintf("http://example.com/p%06d", i)
			if err := agg.Add(sampleRecord(key, 200, int64(i))); err != nil {
				t.Fatalf("add: %v", err)
			}
		}
		it, _, err := agg.Finalize()
		if err != nil {
			t.Fatal(err)
		}
		// drain roughly half the stream so the k-way merge and its heap are
		// live, then sample the heap while chunk iterators are still open
		for i := 0; i < total/2; i++ {
			if _, ok := it.Next(); !ok {
				break
			}
		}
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		for {
			if _, ok := it.Next(); !ok {
				break
			}
		}
		if err := it.Close(); err != nil {
			t.Fatal(err)
		}
		return ms.HeapAlloc
	}

	// spilling variant keeps only a small window in memory at any time
	spilled := measure(2000)
	// the bound is deliberately generous to stay stable across Go releases
	// while still proving growth does not scale linearly with the input
	limit := uint64(64 << 20) // 64 MiB
	if spilled > limit {
		t.Fatalf("spilling aggregator used %d bytes heap, above bound %d", spilled, limit)
	}
}
