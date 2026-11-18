package libgobuster

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testResult(path string) StructuredResult {
	return StructuredResult{
		Timestamp:  "2026-11-18T10:00:00.000000001+08:00",
		Plugin:     "directory enumeration",
		Target:     "http://127.0.0.1:8080/",
		Path:       path,
		StatusCode: 200,
		Length:     1234,
		Redirect:   "",
		DurationMs: 12,
	}
}

func TestStructuredWriterFieldOrder(t *testing.T) {
	t.Parallel()
	filename := filepath.Join(t.TempDir(), "out.jsonl")
	w, err := NewStructuredWriter(filename)
	if err != nil {
		t.Fatalf("NewStructuredWriter failed: %v", err)
	}
	if err := w.Write(testResult("/admin")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	got := strings.TrimSpace(string(content))
	want := `{"timestamp":"2026-11-18T10:00:00.000000001+08:00","plugin":"directory enumeration","target":"http://127.0.0.1:8080/","path":"/admin","status_code":200,"length":1234,"redirect":"","duration_ms":12,"is_new":true}`
	if got != want {
		t.Fatalf("field order/schema mismatch:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestStructuredWriterIsNewAndAppend(t *testing.T) {
	t.Parallel()
	filename := filepath.Join(t.TempDir(), "out.jsonl")

	// first run: everything is new
	w, err := NewStructuredWriter(filename)
	if err != nil {
		t.Fatalf("NewStructuredWriter failed: %v", err)
	}
	r := testResult("/admin")
	if err := w.Write(r); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	// same hit again inside the same run is not new
	if err := w.Write(r); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// second run appends to the same file and marks historical hits
	w2, err := NewStructuredWriter(filename)
	if err != nil {
		t.Fatalf("NewStructuredWriter failed: %v", err)
	}
	if err := w2.Write(testResult("/admin")); err != nil { // historical
		t.Fatalf("Write failed: %v", err)
	}
	if err := w2.Write(testResult("/login")); err != nil { // new
		t.Fatalf("Write failed: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer f.Close()

	var isNew []bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var rec StructuredResult
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("invalid JSON line %q: %v", scanner.Text(), err)
		}
		isNew = append(isNew, rec.IsNew)
	}
	want := []bool{true, false, false, true}
	if fmt.Sprint(isNew) != fmt.Sprint(want) {
		t.Fatalf("is_new sequence mismatch: got %v want %v", isNew, want)
	}
}

func TestStructuredWriterConcurrentWrites(t *testing.T) {
	t.Parallel()
	filename := filepath.Join(t.TempDir(), "out.jsonl")
	w, err := NewStructuredWriter(filename)
	if err != nil {
		t.Fatalf("NewStructuredWriter failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Write(testResult(fmt.Sprintf("/p%d", i))); err != nil {
				t.Errorf("Write failed: %v", err)
			}
		}()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 50 {
		t.Fatalf("expected 50 lines, got %d", len(lines))
	}
	for _, line := range lines {
		var rec StructuredResult
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("corrupted/interleaved line %q: %v", line, err)
		}
	}
}

func TestStructuredWriterOpenError(t *testing.T) {
	t.Parallel()
	if _, err := NewStructuredWriter(filepath.Join(t.TempDir(), "does-not-exist", "out.jsonl")); err == nil {
		t.Fatal("expected error for unwritable path")
	}
}

func TestStructuredWriterWriteError(t *testing.T) {
	t.Parallel()
	filename := filepath.Join(t.TempDir(), "out.jsonl")
	w, err := NewStructuredWriter(filename)
	if err != nil {
		t.Fatalf("NewStructuredWriter failed: %v", err)
	}
	// force the file into a broken state
	if err := w.f.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := w.Write(testResult("/admin")); err == nil {
		t.Fatal("expected write error on closed file")
	}
}
