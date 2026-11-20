package gobusterdir

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OJ/gobuster/v3/libgobuster"
)

// recordingServer is a small fixed site used by the recursive tests. Every
// request is counted so tests can assert how often a directory was actually
// scanned.
type recordingServer struct {
	mu       sync.Mutex
	hits     map[string]int
	dirs     map[string]bool
	redirect map[string]string
}

func newRecordingServer(dirs []string) *recordingServer {
	s := &recordingServer{
		hits:     map[string]int{},
		dirs:     map[string]bool{},
		redirect: map[string]string{},
	}
	for _, d := range dirs {
		s.dirs[d] = true
	}
	return s
}

func (s *recordingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits[r.URL.Path]++
	location, redirects := s.redirect[r.URL.Path]
	isDir := s.dirs[r.URL.Path]
	withoutSlash := !strings.HasSuffix(r.URL.Path, "/")
	dirWithoutSlash := withoutSlash && s.dirs[r.URL.Path+"/"]
	// Underscore-prefixed names are plain files whose body also happens to
	// contain the directory marker; they must not look like directories.
	isFile := strings.HasPrefix(r.URL.Path, "/_")
	s.mu.Unlock()

	switch {
	case redirects:
		http.Redirect(w, r, location, http.StatusMovedPermanently)
	case isFile:
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("file"))
	case isDir:
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("directory"))
	case dirWithoutSlash:
		// A request without the trailing slash still names the directory and
		// is redirected to it, mirroring what real servers do.
		http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("missing"))
	}
}

func (s *recordingServer) hitCount(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

func (s *recordingServer) totalHits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, n := range s.hits {
		total += n
	}
	return total
}

type recursionRun struct {
	paths    []string
	expanded int
	messages []string
}

func runRecursiveDir(t *testing.T, srv *recordingServer, words []string, configure func(*OptionsDir, *libgobuster.Options)) recursionRun {
	t.Helper()

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("could not parse URL: %v", err)
	}

	wordlist := t.TempDir() + "/words.txt"
	if err := os.WriteFile(wordlist, []byte(strings.Join(words, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("could not write wordlist: %v", err)
	}

	global := &libgobuster.Options{
		Threads:    4,
		Wordlist:   wordlist,
		NoProgress: true,
		Quiet:      true,
	}

	opts := NewOptions()
	opts.URL = u
	opts.Timeout = 5 * time.Second
	opts.StatusCodes = "404"
	opts.StatusCodesBlacklist = "404"
	opts.StatusCodesBlacklistParsed.Add(404)

	global.Recursion = true
	global.RecursionDepth = 3
	global.RecursionMaxTargets = 100

	if configure != nil {
		configure(opts, global)
	}

	log := libgobuster.NewLogger(false)
	plugin, err := New(global, opts, log)
	if err != nil {
		t.Fatalf("could not create plugin: %v", err)
	}

	g, err := libgobuster.NewGobuster(global, plugin, log)
	if err != nil {
		t.Fatalf("could not create gobuster: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var mu sync.Mutex
	var results []string
	var messages []string

	resultDone := make(chan struct{})
	go func() {
		defer close(resultDone)
		for r := range g.Progress.ResultChan {
			text, err := r.ResultToString()
			if err != nil {
				continue
			}
			text = strings.TrimSpace(text)
			if text == "" {
				continue
			}
			mu.Lock()
			results = append(results, strings.Fields(text)[0])
			mu.Unlock()
		}
	}()

	messageDone := make(chan struct{})
	go func() {
		defer close(messageDone)
		for msg := range g.Progress.MessageChan {
			mu.Lock()
			messages = append(messages, msg.Message)
			mu.Unlock()
		}
	}()

	errorDone := make(chan struct{})
	go func() {
		defer close(errorDone)
		for range g.Progress.ErrorChan {
		}
	}()

	if err := g.Run(ctx); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	<-resultDone
	<-messageDone
	<-errorDone

	sort.Strings(results)
	run := recursionRun{paths: results, messages: messages}
	for _, msg := range messages {
		if strings.HasPrefix(msg, "recursive scan finished:") {
			var n int
			if _, err := fmtSscanf(msg, &n); err == nil {
				run.expanded = n
			}
		}
	}
	return run
}

// fmtSscanf extracts the expanded-directory count from the finishing message,
// e.g. "recursive scan finished: 4 directories expanded (depth limit 3)".
func fmtSscanf(msg string, n *int) (int, error) {
	fields := strings.Fields(msg)
	if len(fields) < 4 {
		return 0, errInvalidSummary
	}
	value := 0
	for _, r := range fields[3] {
		if r < '0' || r > '9' {
			return 0, errInvalidSummary
		}
		value = value*10 + int(r-'0')
	}
	*n = value
	return 1, nil
}

var errInvalidSummary = os.ErrInvalid

func TestRecursiveScanThreeLevels(t *testing.T) {
	t.Parallel()

	srv := newRecordingServer([]string{
		"/admin/",
		"/admin/users/",
		"/admin/users/list/",
	})

	run := runRecursiveDir(t, srv, []string{"admin", "users", "list", "missing"}, nil)

	// Depth 3: /admin (1), /admin/users (2), /admin/users/list (3).
	// The level-3 directory is reported but not expanded.
	want := []string{"/admin", "/admin/users", "/admin/users/list"}
	if strings.Join(run.paths, " ") != strings.Join(want, " ") {
		t.Fatalf("unexpected result set:\n got: %v\nwant: %v", run.paths, want)
	}

	// Root (depth 0) plus three descended directories.
	if run.expanded != 4 {
		t.Fatalf("expected 4 expanded directories, got %d", run.expanded)
	}

	// Four layers (root at depth 0 plus three descended directories) replay
	// all four words. Each new base additionally runs the existing PreRun
	// wildcard check, which issues two requests.
	const words, precheckRequests = 4, 2
	if got, want := srv.totalHits(), 4*(words+precheckRequests); got != want {
		t.Fatalf("expected %d requests, got %d", want, got)
	}

	// The deepest layer must not be expanded: no request below it.
	if hits := srv.hitCount("/admin/users/list/missing"); hits != 1 {
		t.Fatalf("deepest layer should be scanned once, got %d", hits)
	}
	if hits := srv.hitCount("/admin/users/list/admin/missing"); hits != 0 {
		t.Fatalf("depth limit exceeded, got %d requests below the deepest layer", hits)
	}
}

func TestRecursiveDepthZeroDoesNotExpand(t *testing.T) {
	t.Parallel()

	srv := newRecordingServer([]string{"/admin/"})

	run := runRecursiveDir(t, srv, []string{"admin", "missing"}, func(opts *OptionsDir, global *libgobuster.Options) {
		global.RecursionDepth = 0
	})

	if strings.Join(run.paths, " ") != "/admin" {
		t.Fatalf("unexpected results: %v", run.paths)
	}
	if got := srv.totalHits(); got != 2+2 {
		// Two words for the single layer plus the two PreRun requests.
		t.Fatalf("depth 0 must not expand: expected 4 requests, got %d", got)
	}
	if run.expanded != 1 {
		t.Fatalf("expected only the root layer, got %d", run.expanded)
	}
}

func TestRecursiveDeduplicatesCaseAndSlashVariants(t *testing.T) {
	t.Parallel()

	srv := newRecordingServer([]string{"/admin/"})
	// Non-slash and differently-cased spellings point at the same directory.
	srv.redirect["/admin"] = "/admin/"
	srv.redirect["/Admin"] = "/admin/"

	run := runRecursiveDir(t, srv, []string{"admin", "admin/", "Admin", "missing"}, nil)

	// /admin must be expanded exactly once despite three spellings.
	if hits := srv.hitCount("/admin/missing"); hits != 1 {
		t.Fatalf("expected /admin to be expanded once, got %d expansions", hits)
	}
	if run.expanded != 2 {
		t.Fatalf("expected root + /admin expanded, got %d", run.expanded)
	}

	seen := map[string]int{}
	for _, p := range run.paths {
		seen[p]++
	}
	// The hits are still reported individually, but the directory scan is not
	// repeated.
	if seen["/admin/"] != 1 || seen["/admin"] != 1 || seen["/Admin"] != 1 {
		t.Fatalf("unexpected reported hits: %v", run.paths)
	}
}

func TestRecursiveRedirectToDirectoryAndCrossHostDrop(t *testing.T) {
	t.Parallel()

	srv := newRecordingServer([]string{"/real/"})
	srv.redirect["/moved"] = "/real/"
	srv.redirect["/external"] = "http://other.example.com/elsewhere/"

	runRecursiveDir(t, srv, []string{"moved", "external", "missing"}, nil)

	if hits := srv.hitCount("/real/missing"); hits != 1 {
		t.Fatalf("redirect target should be expanded once, got %d", hits)
	}
	for path := range srv.hits {
		if strings.Contains(path, "other.example.com") || strings.Contains(path, "elsewhere") {
			t.Fatalf("cross-host redirect must never be requested, saw %q", path)
		}
	}
}

func TestRecursiveLoopConverges(t *testing.T) {
	t.Parallel()

	srv := newRecordingServer([]string{"/loop/"})
	srv.redirect["/loop"] = "/loop/"
	srv.redirect["/loop/back"] = "/"

	run := runRecursiveDir(t, srv, []string{"loop", "back", "missing"}, nil)

	// Root and the loop directory are each expanded once. The redirect back to
	// the visited root stops at the record; the self-linking directory does
	// not produce an endless chain.
	if run.expanded != 2 {
		t.Fatalf("expected two expanded layers, got %d", run.expanded)
	}
	if hits := srv.hitCount("/loop/missing"); hits != 1 {
		t.Fatalf("expected /loop to be expanded once, got %d", hits)
	}
}

func TestRecursiveExcludePath(t *testing.T) {
	t.Parallel()

	srv := newRecordingServer([]string{"/admin/", "/private/"})

	run := runRecursiveDir(t, srv, []string{"admin/", "private/", "missing"}, func(opts *OptionsDir, _ *libgobuster.Options) {
		opts.RecursionExcludePaths = []string{"private"}
	})

	// The excluded hit is still reported under the normal filters; only its
	// expansion is suppressed.
	if hits := srv.hitCount("/private/missing"); hits != 0 {
		t.Fatalf("excluded path must not be expanded, got %d requests", hits)
	}
	if hits := srv.hitCount("/admin/missing"); hits != 1 {
		t.Fatalf("non-excluded directory should still expand once, got %d", hits)
	}
	seen := map[string]bool{}
	for _, p := range run.paths {
		seen[p] = true
	}
	if !seen["/private/"] || !seen["/admin/"] {
		t.Fatalf("expected both hits to be reported: %v", run.paths)
	}
	if len(run.paths) != 2 {
		t.Fatalf("expected exactly the two directory hits, got %v", run.paths)
	}
}

func TestRecursiveExcludeStatusAndLength(t *testing.T) {
	t.Parallel()

	t.Run("status", func(t *testing.T) {
		t.Parallel()
		srv := newRecordingServer([]string{"/admin/"})

		run := runRecursiveDir(t, srv, []string{"admin/", "missing"}, func(opts *OptionsDir, _ *libgobuster.Options) {
			opts.RecursionExcludeStatusP.Add(200)
		})

		if hits := srv.hitCount("/admin/missing"); hits != 0 {
			t.Fatalf("status-excluded directory must not expand, got %d", hits)
		}
		if strings.Join(run.paths, " ") != "/admin/" {
			t.Fatalf("status-excluded hit should still be reported: %v", run.paths)
		}
	})

	t.Run("length", func(t *testing.T) {
		t.Parallel()
		srv := newRecordingServer([]string{"/admin/"})

		run := runRecursiveDir(t, srv, []string{"admin/", "missing"}, func(opts *OptionsDir, _ *libgobuster.Options) {
			opts.RecursionExcludeLenP.Add(len("directory"))
		})

		if hits := srv.hitCount("/admin/missing"); hits != 0 {
			t.Fatalf("length-excluded directory must not expand, got %d", hits)
		}
		if strings.Join(run.paths, " ") != "/admin/" {
			t.Fatalf("length-excluded hit should still be reported: %v", run.paths)
		}
	})
}

func TestRecursiveExpandOnlySuppressesOutput(t *testing.T) {
	t.Parallel()

	srv := newRecordingServer([]string{"/silent/"})

	run := runRecursiveDir(t, srv, []string{"silent/", "missing"}, func(opts *OptionsDir, _ *libgobuster.Options) {
		opts.RecursionExpandOnly = []string{"silent"}
	})

	for _, p := range run.paths {
		if strings.Contains(p, "silent") {
			t.Fatalf("expand-only path must not be reported: %v", run.paths)
		}
	}
	if hits := srv.hitCount("/silent/missing"); hits != 1 {
		t.Fatalf("expand-only path must still be expanded once, got %d", hits)
	}
}

func TestRecursiveMaxTargetsTruncates(t *testing.T) {
	t.Parallel()

	srv := newRecordingServer([]string{"/a/", "/b/", "/c/"})

	run := runRecursiveDir(t, srv, []string{"a/", "b/", "c/", "missing"}, func(opts *OptionsDir, global *libgobuster.Options) {
		global.RecursionMaxTargets = 1
	})

	expansions := 0
	for _, name := range []string{"a", "b", "c"} {
		if srv.hitCount("/"+name+"/missing") > 0 {
			expansions++
		}
	}
	if expansions != 1 {
		t.Fatalf("expected exactly one expanded directory, got %d", expansions)
	}
	if run.expanded != 2 {
		t.Fatalf("expected root + one directory, got %d", run.expanded)
	}

	truncated := false
	for _, msg := range run.messages {
		if strings.Contains(msg, "truncated") {
			truncated = true
		}
	}
	if !truncated {
		t.Fatalf("expected a truncation warning, got %v", run.messages)
	}
}

func TestRecursiveExtensionLayersAreNotExpanded(t *testing.T) {
	t.Parallel()

	// /index.php is a file, even though this fixture would otherwise answer
	// /index.php/ with a directory body. It must be reported but never used as
	// a base directory.
	srv := newRecordingServer([]string{"/index.php/"})

	run := runRecursiveDir(t, srv, []string{"index"}, func(opts *OptionsDir, _ *libgobuster.Options) {
		opts.ExtensionsParsed.Add("php")
	})

	if run.expanded != 1 {
		t.Fatalf("file layers must not be expanded, got %d expanded", run.expanded)
	}
	if hits := srv.hitCount("/index.php/missing"); hits != 0 {
		t.Fatalf("extension hits must not be expanded, got %d requests", hits)
	}
	// The file hit itself is still reported.
	found := false
	for _, p := range run.paths {
		if p == "/index.php" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected /index.php to be reported, got %v", run.paths)
	}
}

func TestValidateRecursionRejectsConflicts(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name   string
		mutate func(*OptionsDir)
		match  string
	}{
		{
			name: "same path excluded and expand-only",
			mutate: func(o *OptionsDir) {
				o.RecursionExcludePaths = []string{"admin"}
				o.RecursionExpandOnly = []string{"/admin/"}
			},
			match: "conflict",
		},
		{
			name: "empty exclude pattern",
			mutate: func(o *OptionsDir) {
				o.RecursionExcludePaths = []string{"  "}
			},
			match: "recursion-exclude-path",
		},
		{
			name: "invalid glob",
			mutate: func(o *OptionsDir) {
				o.RecursionExcludePaths = []string{"admin/["}
			},
			match: "recursion-exclude-path",
		},
		{
			name: "exclude every accepted status",
			mutate: func(o *OptionsDir) {
				o.StatusCodesParsed = libgobuster.NewSet[int]()
				o.StatusCodesParsed.Add(200)
				o.StatusCodesBlacklistParsed = libgobuster.NewSet[int]()
				o.RecursionExcludeStatusP = libgobuster.NewSet[int]()
				o.RecursionExcludeStatusP.Add(200)
			},
			match: "recursion-exclude-status",
		},
	}

	for _, x := range tt {
		t.Run(x.name, func(t *testing.T) {
			t.Parallel()
			o := NewOptions()
			o.StatusCodesBlacklistParsed.Add(404)
			x.mutate(o)

			err := o.ValidateRecursion()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), x.match) {
				t.Fatalf("error %q does not mention %q", err, x.match)
			}
		})
	}
}

func TestIsDirectoryPath(t *testing.T) {
	t.Parallel()

	tt := []struct {
		path string
		want bool
	}{
		{"admin/", true},
		{"admin", true},
		{"admin/users", true},
		{"index.php", false},
		{"admin/config.json", false},
		{".git/", true},
		{".well-known/acme", true},
		{"backup.txt.bak", false},
	}

	for _, x := range tt {
		if got := isDirectoryPath(x.path); got != x.want {
			t.Fatalf("isDirectoryPath(%q) = %v, want %v", x.path, got, x.want)
		}
	}
}

func TestMatchesAnyPath(t *testing.T) {
	t.Parallel()

	patterns := []string{"admin", "private/*", "*.bak"}

	tt := []struct {
		path    string
		matched bool
	}{
		{"admin", true},
		{"admin/users", true},
		{"administrator", false},
		{"private/keys", true},
		{"private", false},
		{"index.bak", true},
		{"nested/index.bak", true},
		{"index.php", false},
	}

	for _, x := range tt {
		if _, got := matchesAnyPath(patterns, x.path); got != x.matched {
			t.Fatalf("matchesAnyPath(%q) = %v, want %v", x.path, got, x.matched)
		}
	}
}

func TestNonRecursiveBehaviourUnchanged(t *testing.T) {
	t.Parallel()

	srv := newRecordingServer([]string{"/admin/", "/files/"})
	srv.redirect["/moved"] = "/admin/"

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	wordlist := t.TempDir() + "/words.txt"
	if err := os.WriteFile(wordlist, []byte("admin/\nmoved\nmissing\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := NewOptions()
	opts.URL = u
	opts.Timeout = 5 * time.Second
	opts.StatusCodes = "404"
	opts.StatusCodesBlacklist = "404"
	opts.StatusCodesBlacklistParsed.Add(404)

	global := &libgobuster.Options{
		Threads:    2,
		Wordlist:   wordlist,
		NoProgress: true,
		Quiet:      true,
	}

	plugin, err := New(global, opts, libgobuster.NewLogger(false))
	if err != nil {
		t.Fatal(err)
	}

	g, err := libgobuster.NewGobuster(global, plugin, libgobuster.NewLogger(false))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var results []string
	var resultErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		for r := range g.Progress.ResultChan {
			text, err := r.ResultToString()
			if err != nil {
				resultErr = err
				continue
			}
			results = append(results, strings.TrimSpace(text))
		}
	}()
	go func() {
		for range g.Progress.MessageChan {
		}
	}()
	go func() {
		for range g.Progress.ErrorChan {
		}
	}()

	if err := g.Run(ctx); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	<-done
	if resultErr != nil {
		t.Fatal(resultErr)
	}

	sort.Strings(results)
	// Single-layer output must stay word-relative and byte-for-byte identical
	// to the pre-recursion format.
	want := []string{
		"admin/               (Status: 200) [Size: 9]",
		"moved                (Status: 301) [Size: 42] [--> /admin/]",
	}
	if strings.Join(results, "\n") != strings.Join(want, "\n") {
		t.Fatalf("single-layer output changed:\n got: %#v\nwant: %#v", results, want)
	}
	if g.Progress.RequestsExpected() != g.Progress.RequestsIssued() {
		t.Fatalf("progress mismatch: expected %d issued %d", g.Progress.RequestsExpected(), g.Progress.RequestsIssued())
	}
	if g.Progress.RequestsIssued() != 3 {
		t.Fatalf("expected 3 issued requests, got %d", g.Progress.RequestsIssued())
	}

	// Two PreRun requests plus the three wordlist words. Any expansion would
	// add a further replay below /admin/ and change this count.
	if got, want := srv.totalHits(), 2+3; got != want {
		t.Fatalf("single-layer run issued %d requests, want %d", got, want)
	}
}
