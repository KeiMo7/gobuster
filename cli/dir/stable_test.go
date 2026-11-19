package dir

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internalcli "github.com/OJ/gobuster/v3/cli"
	"github.com/OJ/gobuster/v3/gobusterdir"
	"github.com/OJ/gobuster/v3/libgobuster"
)

// stableTestServer serves a deterministic body per path so exclude-length and
// status filtering have something to work with. The root returns 200 so the
// wildcard precheck (which probes a random non existing path) sees 404 and
// does not abort the run with a WildcardError.
func stableTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("root"))
		case "/admin", "/admin/":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin-page"))
		case "/login":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("login-page-content"))
		case "/redirect":
			http.Redirect(w, req, "/admin", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not-found-body"))
		}
	})
	return httptest.NewServer(mux)
}

func writeWordlist(t *testing.T, dir string, lines []string) string {
	t.Helper()
	name := filepath.Join(dir, "wordlist.txt")
	if err := os.WriteFile(name, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("wordlist: %v", err)
	}
	return name
}

func newStableDirPlugin(t *testing.T, serverURL string, global *libgobuster.Options, mutate ...func(*gobusterdir.OptionsDir)) *gobusterdir.GobusterDir {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	opts := gobusterdir.NewOptions()
	opts.URL = u
	opts.Timeout = 10 * time.Second
	opts.StatusCodes = "200,302"
	parsed, err := libgobuster.ParseCommaSeparatedInt(opts.StatusCodes)
	if err != nil {
		t.Fatalf("parse statuses: %v", err)
	}
	opts.StatusCodesParsed = parsed
	for _, fn := range mutate {
		fn(opts)
	}
	log := libgobuster.NewLogger(false)
	plugin, err := gobusterdir.New(global, opts, log)
	if err != nil {
		t.Fatalf("plugin: %v", err)
	}
	return plugin
}

// captureRun executes gobuster with stdout/stderr redirected to temporary
// files and returns the captured result stream. Files (not pipes) are used so
// there is neither read/write racing nor pipe backpressure.
func captureRun(t *testing.T, global *libgobuster.Options, plugin *gobusterdir.GobusterDir) string {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	outFile, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatalf("stdout temp: %v", err)
	}
	errFile, err := os.CreateTemp(t.TempDir(), "stderr-*")
	if err != nil {
		t.Fatalf("stderr temp: %v", err)
	}
	os.Stdout, os.Stderr = outFile, errFile
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()

	log := libgobuster.NewLogger(false)
	runErr := internalcli.Gobuster(context.Background(), global, plugin, log)

	if err := outFile.Sync(); err != nil {
		t.Fatalf("sync stdout: %v", err)
	}
	outBytes, readErr := os.ReadFile(outFile.Name())
	_ = outFile.Close()
	_ = errFile.Close()
	if runErr != nil {
		errBytes, _ := os.ReadFile(errFile.Name())
		t.Fatalf("run: %v\nstderr: %s", runErr, string(errBytes))
	}
	if readErr != nil {
		t.Fatalf("read stdout: %v", readErr)
	}
	return string(outBytes)
}

func TestStableDirDedupSortAndDeterminism(t *testing.T) {
	// These tests swap the process wide os.Stdout/os.Stderr, so they cannot
	// run in parallel with each other.
	server := stableTestServer(t)
	defer server.Close()

	tmp := t.TempDir()
	// duplicate rows (admin twice) and extensions that do not resolve to
	// different keys, forcing the dedup path
	wordlist := writeWordlist(t, tmp, []string{"admin", "login", "admin", "nope"})

	buildOpts := func() *libgobuster.Options {
		return &libgobuster.Options{
			Threads:         8,
			Wordlist:        wordlist,
			NoProgress:      true,
			Quiet:           true,
			Stable:          true,
			OutputFormat:    libgobuster.OutputFormatText,
			StableChunkSize: 2, // force external merge within the tiny set
		}
	}

	first := captureRun(t, buildOpts(), newStableDirPlugin(t, server.URL, buildOpts()))
	second := captureRun(t, buildOpts(), newStableDirPlugin(t, server.URL, buildOpts()))

	if first != second {
		t.Fatalf("two runs must be byte identical:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}

	lines := strings.Split(strings.TrimRight(first, "\n"), "\n")
	// admin and login only; the duplicate admin row and the 404 are gone
	wantOrder := []string{"admin", "login"}
	if len(lines) != len(wantOrder) {
		t.Fatalf("expected %d unique rows, got %d: %q", len(wantOrder), len(lines), first)
	}
	for i, want := range wantOrder {
		if !strings.HasPrefix(lines[i], want) {
			t.Fatalf("line %d must start with %q, got %q", i, want, lines[i])
		}
		if strings.Contains(lines[i], "  ") {
			t.Fatalf("stable output must not contain fixed width padding: %q", lines[i])
		}
	}
	if strings.Index(first, "admin") > strings.Index(first, "login") {
		t.Fatalf("output is not sorted:\n%s", first)
	}
}

func TestStableDirFileAndStdoutAreIdentical(t *testing.T) {
	server := stableTestServer(t)
	defer server.Close()
	tmp := t.TempDir()
	wordlist := writeWordlist(t, tmp, []string{"admin", "login", "admin"})
	outFile := filepath.Join(tmp, "out.txt")

	global := &libgobuster.Options{
		Threads:         4,
		Wordlist:        wordlist,
		NoProgress:      true,
		Quiet:           true,
		Stable:          true,
		OutputFilename:  outFile,
		StableChunkSize: 50,
	}

	stdout := captureRun(t, global, newStableDirPlugin(t, server.URL, global))

	fileBytes, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if string(fileBytes) != stdout {
		t.Fatalf("stdout and file output must be byte identical:\nstdout=%q\nfile=%q", stdout, string(fileBytes))
	}
}

func TestStableDirTSVAndHiddenPlaceholders(t *testing.T) {
	// not parallel: captureRun swaps process wide standard streams
	server := stableTestServer(t)
	defer server.Close()
	tmp := t.TempDir()
	wordlist := writeWordlist(t, tmp, []string{"admin"})

	global := &libgobuster.Options{
		Threads:      2,
		Wordlist:     wordlist,
		NoProgress:   true,
		Quiet:        true,
		Stable:       true,
		OutputFormat: libgobuster.OutputFormatTSV,
		NoChain:      true,
	}

	out := captureRun(t, global, newStableDirPlugin(t, server.URL, global))
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header plus one row, got %q", out)
	}
	header := strings.Split(lines[0], "\t")
	if len(header) != 9 {
		t.Fatalf("tsv must expose the fixed 9 column layout, got %d", len(header))
	}
	row := strings.Split(lines[1], "\t")
	if row[4] != "200" {
		t.Fatalf("status column wrong: %q", row[4])
	}
	if row[5] != "10" {
		t.Fatalf("real length 10 must render as 10: %q", row[5])
	}
	// empty optional fields must use the unified placeholder rather than
	// an empty string
	for idx, name := range map[int]string{6: "location", 7: "chain", 8: "extra"} {
		if row[idx] != libgobuster.EmptyValue {
			t.Fatalf("%s column must be the empty placeholder %q, got %q", name, libgobuster.EmptyValue, row[idx])
		}
	}
}

func TestStableDirHiddenValuesDifferFromZero(t *testing.T) {
	// not parallel: captureRun swaps process wide standard streams
	server := stableTestServer(t)
	defer server.Close()
	tmp := t.TempDir()
	wordlist := writeWordlist(t, tmp, []string{"admin"})

	global := &libgobuster.Options{
		Threads:      1,
		Wordlist:     wordlist,
		NoProgress:   true,
		Quiet:        true,
		Stable:       true,
		OutputFormat: libgobuster.OutputFormatTSV,
		NoChain:      true,
	}

	plugin := newStableDirPlugin(t, server.URL, global, func(o *gobusterdir.OptionsDir) {
		// emulate --no-status and --hide-length so the hidden marker is
		// exercised end to end
		o.NoStatus = true
		o.HideLength = true
	})

	out := captureRun(t, global, plugin)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header plus one row, got %q", out)
	}
	row := strings.Split(lines[1], "\t")
	if row[4] != libgobuster.HiddenValue {
		t.Fatalf("hidden status must render as %q, got %q", libgobuster.HiddenValue, row[4])
	}
	if row[5] != libgobuster.HiddenValue {
		t.Fatalf("hidden length must render as %q, got %q", libgobuster.HiddenValue, row[5])
	}
}

func TestStableDirFilteredCounters(t *testing.T) {
	// not parallel: uses a shared test server and process level state
	server := stableTestServer(t)
	defer server.Close()

	global := &libgobuster.Options{Threads: 2, Stable: true}

	plugin := newStableDirPlugin(t, server.URL, global, func(o *gobusterdir.OptionsDir) {
		excluded, err := libgobuster.ParseCommaSeparatedInt("18")
		if err != nil {
			t.Fatalf("parse exclude length: %v", err)
		}
		o.ExcludeLengthParsed = excluded
	})
	if err := plugin.PreRun(context.Background(), libgobuster.NewProgress()); err != nil {
		t.Fatalf("prerun: %v", err)
	}

	progress := libgobuster.NewProgress()
	cases := []struct {
		word          string
		wantFiltered  libgobuster.FilterReason
		wantResultNil bool
	}{
		{word: "admin"}, // 200, length 10 -> result
		{word: "login", wantFiltered: libgobuster.FilterLength, wantResultNil: true},
		{word: "nope", wantFiltered: libgobuster.FilterStatus, wantResultNil: true},
	}

	for _, tc := range cases {
		res, err := plugin.ProcessWord(context.Background(), tc.word, progress)
		if err != nil {
			t.Fatalf("process %s: %v", tc.word, err)
		}
		if tc.wantResultNil && res != nil {
			t.Fatalf("word %q must be filtered, got %#v", tc.word, res)
		}
		if !tc.wantResultNil && res == nil {
			t.Fatalf("word %q must produce a result", tc.word)
		}
	}

	if got := progress.FilteredLength(); got != 1 {
		t.Fatalf("expected 1 length filtered request, got %d", got)
	}
	if got := progress.FilteredStatus(); got != 1 {
		t.Fatalf("expected 1 status filtered request, got %d", got)
	}
	if got := progress.FilteredTotal(); got != 2 {
		t.Fatalf("expected 2 total filtered requests, got %d", got)
	}
	if got := progress.FilteredWildcard(); got != 0 {
		t.Fatalf("expected no wildcard filtered requests, got %d", got)
	}
}
