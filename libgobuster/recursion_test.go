package libgobuster

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestCanonicalTargetFoldsVariants(t *testing.T) {
	t.Parallel()

	variants := []string{
		"http://example.com/admin/",
		"HTTP://Example.COM/Admin/",
		"http://example.com//admin",
		"http://example.com/admin//",
		"http://example.com/admin/./",
		"http://example.com/Admin/../admin/",
	}

	var want string
	for i, v := range variants {
		got, ok := canonicalTarget(v)
		if !ok {
			t.Fatalf("canonicalTarget(%q) returned not ok", v)
		}
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("canonicalTarget(%q) = %q, want %q", v, got, want)
		}
	}

	if want != "http://example.com/admin" {
		t.Fatalf("unexpected canonical key %q", want)
	}
}

func TestCanonicalTargetRejectsMissingHost(t *testing.T) {
	t.Parallel()

	if _, ok := canonicalTarget("/just/a/path/"); ok {
		t.Fatal("expected path-only target to be rejected")
	}
}

func TestVisitedSetVisitIsAtomic(t *testing.T) {
	t.Parallel()

	const goroutines = 64
	visited := newVisitedSet(0)

	var wg sync.WaitGroup
	var added int
	var mu sync.Mutex

	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			wasAdded, truncated := visited.Visit("http://example.com/admin")
			if truncated {
				t.Error("unexpected truncation with unlimited set")
			}
			if wasAdded {
				mu.Lock()
				added++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if added != 1 {
		t.Fatalf("expected exactly one goroutine to add the key, got %d", added)
	}
	if visited.Len() != 1 {
		t.Fatalf("expected one visited entry, got %d", visited.Len())
	}
}

func TestVisitedSetLimitReportsTruncation(t *testing.T) {
	t.Parallel()

	visited := newVisitedSet(2)

	if added, truncated := visited.Visit("a"); !added || truncated {
		t.Fatalf("first visit: added=%v truncated=%v", added, truncated)
	}
	if added, truncated := visited.Visit("b"); !added || truncated {
		t.Fatalf("second visit: added=%v truncated=%v", added, truncated)
	}
	if added, truncated := visited.Visit("c"); added || !truncated {
		t.Fatalf("third visit should be truncated: added=%v truncated=%v", added, truncated)
	}
	if added, truncated := visited.Visit("a"); added || truncated {
		t.Fatalf("existing key should be a duplicate, not a truncation: added=%v truncated=%v", added, truncated)
	}
}

type fakeRecursiveResult struct {
	target string
}

func (f fakeRecursiveResult) ResultToString() (string, error) { return f.target, nil }
func (f fakeRecursiveResult) RecursiveTarget() string         { return f.target }

func TestRecursionStateEnforcesDepthBeforeQueueing(t *testing.T) {
	t.Parallel()

	state := newRecursionState(2, 0)
	state.depth = 2

	if enqueued, _ := state.considerResult(fakeRecursiveResult{target: "http://example.com/too/deep/"}); enqueued {
		t.Fatal("directory one level past the limit must not be queued")
	}
	if len(state.queue) != 0 {
		t.Fatalf("queue should stay empty, got %d entries", len(state.queue))
	}

	state.depth = 1
	if enqueued, _ := state.considerResult(fakeRecursiveResult{target: "http://example.com/allowed/"}); !enqueued {
		t.Fatal("directory at the limit should be queued")
	}
	if len(state.queue) != 1 {
		t.Fatalf("expected one queued directory, got %d", len(state.queue))
	}
	if state.queue[0].depth != 2 {
		t.Fatalf("expected queued depth 2, got %d", state.queue[0].depth)
	}
}

func TestRecursionStateDeduplicatesVariants(t *testing.T) {
	t.Parallel()

	state := newRecursionState(5, 0)
	state.depth = 0

	for _, target := range []string{
		"http://example.com/Admin/",
		"http://example.com/admin",
		"http://example.com//admin/",
	} {
		if enqueued, _ := state.considerResult(fakeRecursiveResult{target: target}); !enqueued && len(state.queue) == 0 {
			t.Fatalf("first target %q should be queued", target)
		}
	}

	if len(state.queue) != 1 {
		t.Fatalf("expected only one queued directory, got %d", len(state.queue))
	}
}

func TestRecursionStateSeedIsNotExpanded(t *testing.T) {
	t.Parallel()

	state := newRecursionState(5, 0)
	state.seed("http://example.com/")

	// A redirect that points back at the root must not be expanded again.
	if enqueued, _ := state.considerResult(fakeRecursiveResult{target: "http://example.com/"}); enqueued {
		t.Fatal("root target should not be queued again")
	}
}

func TestRecursionStateTruncation(t *testing.T) {
	t.Parallel()

	state := newRecursionState(5, 1)
	state.depth = 0

	if _, truncated := state.considerResult(fakeRecursiveResult{target: "http://example.com/a/"}); truncated {
		t.Fatal("first target should fit")
	}
	enqueued, truncated := state.considerResult(fakeRecursiveResult{target: "http://example.com/b/"})
	if enqueued || !truncated {
		t.Fatalf("second target should be truncated: enqueued=%v truncated=%v", enqueued, truncated)
	}
}

func TestReadWordlistWordsHonoursOffset(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := dir + "/words.txt"
	content := "one\n\ntwo\nthree\nfour\n"
	if err := writeFile(path, content); err != nil {
		t.Fatal(err)
	}

	words, err := readWordlistWords(path, 1)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"two", "three", "four"}
	if strings.Join(words, ",") != strings.Join(want, ",") {
		t.Fatalf("got words %v, want %v", words, want)
	}
}

// latePlugin emits a dynamic discovery word only when the last word of the
// layer is processed. If the layer end were decided before that dynamic work is
// registered, the run would stop early and the late directory would be lost.
type latePlugin struct {
	mu          sync.Mutex
	processed   []string
	targets     []string
	lateDir     string
	lateEmitted bool
}

func (p *latePlugin) Name() string { return "late" }

func (p *latePlugin) PreRun(context.Context, *Progress) error { return nil }

func (p *latePlugin) ProcessWord(_ context.Context, word string, _ *Progress) (Result, error) {
	p.mu.Lock()
	p.processed = append(p.processed, word)
	isLast := word == "last"
	p.mu.Unlock()

	if word == p.lateDir {
		return lateResult{target: "http://example.com/" + p.lateDir + "/"}, nil
	}

	if isLast {
		return lateResult{}, nil
	}

	return nil, nil // nolint:nilnil
}

func (p *latePlugin) AdditionalWords(string) []string { return nil }

func (p *latePlugin) AdditionalWordsLen() int { return 0 }

func (p *latePlugin) AdditionalSuccessWords(word string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	// The late directory is "discovered" as a side effect of the final word.
	if word == "last" && !p.lateEmitted {
		p.lateEmitted = true
		return []string{p.lateDir}
	}
	return nil
}

func (p *latePlugin) GetConfigString() (string, error) { return "", nil }

func (p *latePlugin) RootTarget() string { return "http://example.com/" }

func (p *latePlugin) SetTarget(target string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targets = append(p.targets, target)
	return nil
}

type lateResult struct {
	target string
}

func (r lateResult) ResultToString() (string, error) { return r.target, nil }
func (r lateResult) RecursiveTarget() string         { return r.target }

func TestRecursiveEndsOnlyAfterLateDynamicWork(t *testing.T) {
	t.Parallel()

	wordlist := t.TempDir() + "/words.txt"
	if err := writeFile(wordlist, "first\nlast\n"); err != nil {
		t.Fatal(err)
	}

	plugin := &latePlugin{lateDir: "late"}

	// PreRun only runs for the root; tell the plugin its own precheck result.
	opts := &Options{
		Threads:             4,
		Wordlist:            wordlist,
		Recursion:           true,
		RecursionDepth:      2,
		RecursionMaxTargets: 10,
	}

	g, err := NewGobuster(opts, plugin, NewLogger(false))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range g.Progress.ResultChan {
		}
	}()
	errDone := make(chan struct{})
	go func() {
		defer close(errDone)
		for range g.Progress.ErrorChan {
		}
	}()
	msgDone := make(chan struct{})
	var messages []string
	var mu sync.Mutex
	go func() {
		defer close(msgDone)
		for msg := range g.Progress.MessageChan {
			mu.Lock()
			messages = append(messages, msg.Message)
			mu.Unlock()
		}
	}()

	if err := g.Run(ctx); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	<-done
	<-errDone
	<-msgDone

	plugin.mu.Lock()
	targets := append([]string(nil), plugin.targets...)
	plugin.mu.Unlock()

	if len(targets) != 1 || targets[0] != "http://example.com/late/" {
		t.Fatalf("late dynamic directory was not expanded; targets = %v", targets)
	}
	if !plugin.lateEmitted {
		t.Fatal("late discovery word was never produced")
	}

	truncated := false
	finished := false
	for _, msg := range messages {
		if strings.Contains(msg, "truncated") {
			truncated = true
		}
		if strings.HasPrefix(msg, "recursive scan finished:") {
			finished = true
		}
	}
	if truncated {
		t.Fatalf("unexpected truncation: %v", messages)
	}
	if !finished {
		t.Fatalf("missing finish summary: %v", messages)
	}
}

func TestRecursionRejectsStdinWordlist(t *testing.T) {
	t.Parallel()

	plugin := &latePlugin{lateDir: "late"}
	opts := &Options{
		Threads:        2,
		Wordlist:       "-",
		Recursion:      true,
		RecursionDepth: 2,
	}

	g, err := NewGobuster(opts, plugin, NewLogger(false))
	if err != nil {
		t.Fatal(err)
	}

	// Drain the channels closed by Run.
	go func() {
		for range g.Progress.ResultChan {
		}
	}()
	go func() {
		for range g.Progress.ErrorChan {
		}
	}()
	go func() {
		for range g.Progress.MessageChan {
		}
	}()

	err = g.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "stdin") {
		t.Fatalf("expected a stdin recursion error, got %v", err)
	}
}

// failingPreRunPlugin fails its precheck for one specific target and succeeds
// for the others. The scheduler must report the failure and keep expanding the
// remaining branches instead of aborting the whole run.
type failingPreRunPlugin struct {
	mu       sync.Mutex
	target   string
	expanded []string
}

func (p *failingPreRunPlugin) Name() string { return "failing" }

func (p *failingPreRunPlugin) PreRun(context.Context, *Progress) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.target == "http://example.com/bad/" {
		return errBadBranch
	}
	p.expanded = append(p.expanded, p.target)
	return nil
}

var errBadBranch = os.ErrDeadlineExceeded

func (p *failingPreRunPlugin) ProcessWord(_ context.Context, word string, _ *Progress) (Result, error) {
	p.mu.Lock()
	// SetTarget is not called for the initial root layer.
	target := p.target
	if target == "" {
		target = "http://example.com/"
	}
	p.mu.Unlock()

	if word == "bad" && target == "http://example.com/" {
		return lateResult{target: "http://example.com/bad/"}, nil
	}
	if word == "good" && target == "http://example.com/" {
		return lateResult{target: "http://example.com/good/"}, nil
	}
	return nil, nil // nolint:nilnil
}

func (p *failingPreRunPlugin) AdditionalWords(string) []string { return nil }

func (p *failingPreRunPlugin) AdditionalWordsLen() int { return 0 }

func (p *failingPreRunPlugin) AdditionalSuccessWords(string) []string { return nil }

func (p *failingPreRunPlugin) GetConfigString() (string, error) { return "", nil }

func (p *failingPreRunPlugin) RootTarget() string { return "http://example.com/" }

func (p *failingPreRunPlugin) SetTarget(target string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.target = target
	return nil
}

func TestRecursiveBranchFailureDoesNotAbortRun(t *testing.T) {
	t.Parallel()

	wordlist := t.TempDir() + "/words.txt"
	if err := writeFile(wordlist, "bad\ngood\n"); err != nil {
		t.Fatal(err)
	}

	plugin := &failingPreRunPlugin{}
	opts := &Options{
		Threads:             4,
		Wordlist:            wordlist,
		Recursion:           true,
		RecursionDepth:      2,
		RecursionMaxTargets: 10,
	}

	g, err := NewGobuster(opts, plugin, NewLogger(false))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var errorsSeen []string
	var mu sync.Mutex
	go func() {
		for e := range g.Progress.ResultChan {
			_ = e
		}
	}()
	go func() {
		for range g.Progress.MessageChan {
		}
	}()
	errDone := make(chan struct{})
	go func() {
		defer close(errDone)
		for e := range g.Progress.ErrorChan {
			mu.Lock()
			errorsSeen = append(errorsSeen, e.Error())
			mu.Unlock()
		}
	}()

	if err := g.Run(ctx); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	<-errDone

	plugin.mu.Lock()
	expanded := append([]string(nil), plugin.expanded...)
	plugin.mu.Unlock()

	foundGood := false
	for _, target := range expanded {
		if target == "http://example.com/good/" {
			foundGood = true
		}
		if target == "http://example.com/bad/" {
			t.Fatalf("failing branch must not run its wordlist: %v", expanded)
		}
	}
	if !foundGood {
		t.Fatalf("healthy branch was not expanded: %v", expanded)
	}

	foundError := false
	for _, e := range errorsSeen {
		if strings.Contains(e, "bad") {
			foundError = true
		}
	}
	if !foundError {
		t.Fatalf("branch failure was not reported: %v", errorsSeen)
	}
}
