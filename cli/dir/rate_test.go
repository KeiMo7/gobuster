package dir

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	internalcli "github.com/OJ/gobuster/v3/cli"
	"github.com/OJ/gobuster/v3/gobusterdir"
	"github.com/OJ/gobuster/v3/libgobuster"
)

// rattlingServer answers 429 for the first limitedFor requests and 200 for the
// rest.
type rattlingServer struct {
	limitedFor int64
	requests   atomic.Int64
	server     *httptest.Server
}

func newRattlingServer(t *testing.T, limitedFor int64) *rattlingServer {
	t.Helper()
	s := &rattlingServer{limitedFor: limitedFor}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := s.requests.Add(1)

		// The wildcard probe must not be rate limited, otherwise PreRun fails.
		if strings.Contains(r.URL.Path, "-") && len(strings.Trim(r.URL.Path, "/")) > 30 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if n <= s.limitedFor {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := fmt.Fprint(w, "ok"); err != nil {
			t.Errorf("write: %v", err)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func writeWordlist(t *testing.T, words int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "words.txt")
	var builder strings.Builder
	for i := range words {
		fmt.Fprintf(&builder, "word%d\n", i)
	}
	if err := os.WriteFile(path, []byte(builder.String()), 0o600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}
	return path
}

func newTestDir(t *testing.T, rawURL, wordlist string, threads int, rate libgobuster.RateLimitConfig) (*gobusterdir.GobusterDir, *libgobuster.Options) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	pluginOpts := gobusterdir.NewOptions()
	pluginOpts.URL = u
	pluginOpts.Timeout = 5 * time.Second
	pluginOpts.StatusCodesBlacklist = "404"
	pluginOpts.StatusCodesBlacklistParsed = libgobuster.NewSet[int]()
	pluginOpts.StatusCodesBlacklistParsed.Add(http.StatusNotFound)
	pluginOpts.ExcludeLengthParsed = libgobuster.NewSet[int]()
	pluginOpts.RateLimit = rate

	globalOpts := libgobuster.Options{
		Threads:    threads,
		Wordlist:   wordlist,
		NoProgress: true,
		Quiet:      true,
	}

	log := libgobuster.NewLogger(false)
	plugin, err := gobusterdir.New(&globalOpts, pluginOpts, log)
	if err != nil {
		t.Fatalf("create plugin: %v", err)
	}
	return plugin, &globalOpts
}

// TestDirAdaptiveRateLowersAndRecovers drives a full directory enumeration and
// asserts that the request rate drops after a rate limit signal and climbs
// again once the target stops limiting.
func TestDirAdaptiveRateLowersAndRecovers(t *testing.T) {
	t.Parallel()
	server := newRattlingServer(t, 6)
	serverAddress := server.server.URL
	wordlist := writeWordlist(t, 60)

	plugin, globalOpts := newTestDir(t, server.server.URL, wordlist, 2, libgobuster.RateLimitConfig{
		Adaptive:             true,
		MaxRate:              200,
		MinRate:              5,
		BackoffFactor:        0.5,
		RecoverySuccesses:    5,
		RecoveryFactor:       1.5,
		MaxConsecutiveLimits: -1,
	})

	// Sample the observed rate while the enumeration is running.
	var (
		samplesMu sync.Mutex
		samples   []float64
	)
	target := libgobuster.TargetFromURL(mustParseURL(t, serverAddress))
	stop := make(chan struct{})
	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				samplesMu.Lock()
				samples = append(samples, plugin.RateLimiter().CurrentRate(target))
				samplesMu.Unlock()
			case <-stop:
				return
			}
		}
	}()

	runErr := internalcli.Gobuster(context.Background(), globalOpts, plugin, libgobuster.NewLogger(false))
	close(stop)
	<-samplerDone
	if runErr != nil {
		t.Fatalf("run: %v", runErr)
	}

	samplesMu.Lock()
	defer samplesMu.Unlock()
	minimum := samples[0]
	for _, s := range samples {
		if s < minimum {
			minimum = s
		}
	}
	final := samples[len(samples)-1]
	if minimum >= samples[0] {
		t.Fatalf("rate never dropped: %v", samples)
	}
	if final <= minimum {
		t.Fatalf("rate never recovered: minimum=%v final=%v samples=%v", minimum, final, samples)
	}
	if final > 200 {
		t.Fatalf("rate exceeded the maximum: %v", final)
	}

	history := plugin.RateLimiter().History()
	var limited, recovered bool
	for _, ev := range history {
		switch ev.Event {
		case libgobuster.RateEventLimited:
			limited = true
		case libgobuster.RateEventRecovered:
			recovered = true
		}
	}
	if !limited || !recovered {
		t.Fatalf("expected limited and recovered transitions, got %+v", history)
	}

	// The rate limit responses were retried, so results were still found.
	if got := server.requests.Load(); got < 60 {
		t.Fatalf("only %d requests reached the server, expected at least one per word", got)
	}
}

// TestDirAdaptiveRateStopsOnPersistentLimiting makes sure a target that never
// stops limiting is written off instead of being retried forever.
func TestDirAdaptiveRateStopsOnPersistentLimiting(t *testing.T) {
	t.Parallel()
	server := newRattlingServer(t, 1<<30)
	wordlist := writeWordlist(t, 1000)

	plugin, globalOpts := newTestDir(t, server.server.URL, wordlist, 4, libgobuster.RateLimitConfig{
		Adaptive:             true,
		MaxRate:              500,
		MinRate:              1,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: 6,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	err := internalcli.Gobuster(ctx, globalOpts, plugin, libgobuster.NewLogger(false))
	if err == nil {
		t.Fatal("expected the run to stop with an error")
	}
	if !strings.Contains(err.Error(), "rate limiting") {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("target was retried for %v", elapsed)
	}
	if got := server.requests.Load(); got > 100 {
		t.Fatalf("target received %d requests before being written off", got)
	}
	if !plugin.RateLimiter().AnyExhausted() {
		t.Fatal("limiter did not mark the target as exhausted")
	}
}

// TestDirManualRateOverridesAdaptive checks the manual rate wins and that the
// conflict is surfaced in the configuration output.
func TestDirManualRateOverridesAdaptive(t *testing.T) {
	t.Parallel()
	server := newRattlingServer(t, 1<<30)
	serverAddress := server.server.URL
	wordlist := writeWordlist(t, 4)

	plugin, globalOpts := newTestDir(t, server.server.URL, wordlist, 1, libgobuster.RateLimitConfig{
		Adaptive:             true,
		ManualRate:           20,
		MaxRate:              200,
		MinRate:              1,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: 2,
	})

	config, err := plugin.GetConfigString()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if !strings.Contains(config, "manual rate overrides it") {
		t.Fatalf("config does not announce the override:\n%s", config)
	}

	// The manual rate must not be lowered and the target must not be stopped.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := internalcli.Gobuster(ctx, globalOpts, plugin, libgobuster.NewLogger(false)); err != nil {
		t.Fatalf("run with manual rate: %v", err)
	}
	target := libgobuster.TargetFromURL(mustParseURL(t, serverAddress))
	if got := plugin.RateLimiter().CurrentRate(target); got != 20 {
		t.Fatalf("manual rate was overridden: %v", got)
	}
	if plugin.RateLimiter().AnyExhausted() {
		t.Fatal("manual rate must not stop the target")
	}
}

// TestDirWithoutRateLimitingIsUnchanged runs the same wordlist against the same
// server with and without the adaptive flag and compares the found results.
func TestDirWithoutRateLimitingIsUnchanged(t *testing.T) {
	t.Parallel()
	words := []string{"admin", "images", "index.html", "missing"}

	run := func(t *testing.T, rate libgobuster.RateLimitConfig) ([]string, string) {
		t.Helper()
		mux := http.NewServeMux()
		for _, w := range words {
			if w == "missing" {
				continue
			}
			content := "content-" + w
			mux.HandleFunc("/"+w, func(w http.ResponseWriter, _ *http.Request) {
				if _, err := fmt.Fprint(w, content); err != nil {
					t.Errorf("write: %v", err)
				}
			})
		}
		server := httptest.NewServer(mux)
		t.Cleanup(server.Close)

		wordlist := filepath.Join(t.TempDir(), "words.txt")
		if err := os.WriteFile(wordlist, []byte(strings.Join(words, "\n")+"\n"), 0o600); err != nil {
			t.Fatalf("write wordlist: %v", err)
		}

		plugin, globalOpts := newTestDir(t, server.URL, wordlist, 1, rate)
		var mu sync.Mutex
		var results []string
		// Collect the results the same way the CLI result worker does.
		collectDone := make(chan struct{})
		go func() {
			defer close(collectDone)
			for r := range pluginResults(context.Background(), globalOpts, plugin) {
				s, err := r.ResultToString()
				if err != nil {
					t.Errorf("result: %v", err)
					return
				}
				mu.Lock()
				results = append(results, strings.TrimSpace(s))
				mu.Unlock()
			}
		}()
		<-collectDone

		config, err := plugin.GetConfigString()
		if err != nil {
			t.Fatalf("config: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		return results, config
	}

	baselineResults, baselineConfig := run(t, libgobuster.RateLimitConfig{})
	limitedResults, limitedConfig := run(t, libgobuster.RateLimitConfig{Adaptive: true, MaxRate: 100, MinRate: 1})

	if strings.Join(baselineResults, "|") != strings.Join(limitedResults, "|") {
		t.Fatalf("results changed with rate limiting enabled:\nwithout: %v\nwith:    %v", baselineResults, limitedResults)
	}
	if len(baselineResults) != 3 {
		t.Fatalf("expected 3 results, got %v", baselineResults)
	}

	// The only allowed difference is the added rate limit line.
	baselineLines := strings.Split(baselineConfig, "\n")
	limitedLines := strings.Split(limitedConfig, "\n")
	if len(limitedLines) != len(baselineLines)+1 {
		t.Fatalf("config output changed beyond the added line:\n%s\n---\n%s", baselineConfig, limitedConfig)
	}
}

// pluginResults runs the plugin and forwards the results into a channel.
func pluginResults(ctx context.Context, opts *libgobuster.Options, plugin *gobusterdir.GobusterDir) <-chan libgobuster.Result {
	out := make(chan libgobuster.Result)
	g, err := libgobuster.NewGobuster(opts, plugin, libgobuster.NewLogger(false))
	if err != nil {
		close(out)
		return out
	}
	go func() {
		defer close(out)
		done := make(chan struct{})
		go func() {
			defer close(done)
			for r := range g.Progress.ResultChan {
				out <- r
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
		_ = g.Run(ctx)
		<-done
	}()
	return out
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
