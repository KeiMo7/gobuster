package libgobuster

import (
	"net/url"
	"path"
	"strings"
	"sync"
)

// visitedSet is the concurrency safe record of expanded directories.
//
// Lookup and insertion happen under the same lock so two goroutines can never
// both observe a directory as unseen and expand it twice. The set is bounded:
// once max entries are present, Visit refuses to add more and reports the
// truncation to the caller.
type visitedSet struct {
	mu         sync.Mutex
	seen       map[string]struct{}
	discovered int
	max        int
}

func newVisitedSet(maxEntries int) *visitedSet {
	return &visitedSet{
		seen: make(map[string]struct{}),
		max:  maxEntries,
	}
}

// Visit atomically decides whether key is new. It returns added == true when
// key was not present and is now recorded. When the configured maximum number
// of discovered entries is reached, it returns added == false,
// truncated == true. Already present keys are always reported as duplicates,
// never as truncations.
func (v *visitedSet) Visit(key string) (added bool, truncated bool) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, found := v.seen[key]; found {
		return false, false
	}

	if v.max > 0 && v.discovered >= v.max {
		return false, true
	}

	v.seen[key] = struct{}{}
	v.discovered++
	return true, false
}

// Len returns the number of visited entries, including seeded roots.
func (v *visitedSet) Len() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.seen)
}

// canonicalTarget builds a comparison key for a directory URL. It folds
// together the variants that address the same directory: scheme and host case,
// path case, repeated slashes and a trailing slash. The key is only used for
// deduplication; the original URL is what gets requested.
func canonicalTarget(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}

	p := u.Path
	if p == "" {
		p = "/"
	}
	// path.Clean folds repeated and dot segments; re-add a leading slash
	// because Clean can strip it for relative paths.
	p = path.Clean("/" + p)
	if p != "/" {
		p = strings.TrimSuffix(p, "/")
	}

	var b strings.Builder
	b.WriteString(strings.ToLower(u.Scheme))
	b.WriteString("://")
	b.WriteString(strings.ToLower(u.Host))
	b.WriteString(strings.ToLower(p))
	return b.String(), true
}

// recursionTarget is a directory queued for expansion.
type recursionTarget struct {
	url   string
	depth int
}

// recursionState tracks the expansion frontier. It is owned by the Run
// goroutine; the visited set it uses is safe for concurrent access.
type recursionState struct {
	maxDepth     int
	visited      *visitedSet
	queue        []recursionTarget
	depth        int
	expandedDirs int
	truncated    bool
}

func newRecursionState(maxDepth, maxTargets int) *recursionState {
	return &recursionState{
		maxDepth: maxDepth,
		visited:  newVisitedSet(maxTargets),
	}
}

// seed records the initial base URL so redirects back to it are not expanded
// a second time. The seed is not subject to the visited-target limit: the
// limit bounds discovered directories, not the initial target.
func (s *recursionState) seed(raw string) {
	key, ok := canonicalTarget(raw)
	if !ok {
		return
	}

	s.visited.mu.Lock()
	defer s.visited.mu.Unlock()
	if _, found := s.visited.seen[key]; !found {
		s.visited.seen[key] = struct{}{}
	}
}

// visitAttempt is the outcome of asking the visited set to record a target.
type visitAttempt int

const (
	// visitNew means the target was unseen and is now recorded.
	visitNew visitAttempt = iota
	// visitDuplicate means the target was already recorded.
	visitDuplicate
	// visitTruncated means the record is full; the target was not recorded.
	visitTruncated
)

// considerResult decides whether a successful result starts another scan.
// Depth and deduplication are applied before anything is queued. A suppressed
// result still expands its directory; it is only hidden from normal output.
func (s *recursionState) considerResult(result Result) (enqueued bool, truncated bool) {
	recursive, ok := result.(RecursiveResult)
	if !ok {
		return false, false
	}

	target := recursive.RecursiveTarget()
	if target == "" {
		return false, false
	}

	// Enforce the depth limit before the target can enter the queue.
	childDepth := s.depth + 1
	if childDepth > s.maxDepth {
		return false, false
	}

	key, ok := canonicalTarget(target)
	if !ok {
		return false, false
	}

	switch s.attemptVisit(key) {
	case visitTruncated:
		return false, true
	case visitDuplicate:
		return false, false
	}

	s.queue = append(s.queue, recursionTarget{url: target, depth: childDepth})
	return true, false
}

func (s *recursionState) attemptVisit(key string) visitAttempt {
	added, truncated := s.visited.Visit(key)
	switch {
	case truncated:
		return visitTruncated
	case added:
		return visitNew
	default:
		return visitDuplicate
	}
}

// pop returns the next directory to scan.
func (s *recursionState) pop() (recursionTarget, bool) {
	if len(s.queue) == 0 {
		return recursionTarget{}, false
	}
	target := s.queue[0]
	s.queue = s.queue[1:]
	return target, true
}
