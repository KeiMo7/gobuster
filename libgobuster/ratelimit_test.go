package libgobuster

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock lets the rate limiter tests run without real waiting.
type fakeClock struct {
	mu    sync.Mutex
	now   time.Time
	waits []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1700000000, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.waits = append(c.waits, d)
	c.now = c.now.Add(d)
	return nil
}

func (c *fakeClock) Waits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestLimiter(t *testing.T, clock *fakeClock, cfg RateLimitConfig) *RateLimiter {
	t.Helper()
	cfg.Adaptive = true
	l := NewRateLimiter(cfg, NewLogger(false))
	if l == nil {
		t.Fatal("expected an active rate limiter")
	}
	l.SetQuiet(true)
	l.now = clock.Now
	l.sleep = clock.Sleep
	return l
}

func headers(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

// simulatedResponse is a canned response for driving the limiter directly.
type simulatedResponse struct {
	status int
	header http.Header
}

func (r simulatedResponse) observe(l *RateLimiter, target string) (bool, bool, error) {
	return l.Observe(target, r.status, r.header)
}

func limitedResponse() simulatedResponse {
	// No Retry-After: the cooldown is derived from the current rate.
	return simulatedResponse{status: http.StatusTooManyRequests, header: headers()}
}

func limitedResponseWithRetryAfter(seconds int) simulatedResponse {
	return simulatedResponse{status: http.StatusTooManyRequests, header: headers("Retry-After", strconv.Itoa(seconds))}
}

func okResponse() simulatedResponse {
	return simulatedResponse{status: http.StatusOK, header: headers()}
}

func TestRateLimitDisabledHasNoEffect(t *testing.T) {
	t.Parallel()
	if l := NewRateLimiter(RateLimitConfig{}, NewLogger(false)); l != nil {
		t.Fatal("expected no rate limiter when the feature is disabled")
	}

	// A nil limiter must be usable and never pace.
	var l *RateLimiter
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := l.Acquire(ctx, "http://example.invalid"); err != nil {
		t.Fatalf("nil limiter Acquire returned %v", err)
	}
	if limited, discard, err := l.Observe("http://example.invalid", http.StatusTooManyRequests, headers()); err != nil || limited || discard {
		t.Fatalf("nil limiter Observe returned limited=%v discard=%v err=%v", limited, discard, err)
	}
	if rate, limited := l.LimitedRate(); rate != 0 || limited {
		t.Fatalf("nil limiter reported limited=%v rate=%v", limited, rate)
	}
	if l.Status() != nil || l.History() != nil || l.PendingEvents() != 0 {
		t.Fatal("nil limiter returned state")
	}
}

func TestRateLimitSignalDetection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		status  int
		header  http.Header
		limited bool
		discard bool
		reason  string
	}{
		{"429", http.StatusTooManyRequests, headers(), true, true, "http_429"},
		{"429 with retry-after", http.StatusTooManyRequests, headers("Retry-After", "7"), true, true, "http_429"},
		{"503 with retry-after", http.StatusServiceUnavailable, headers("Retry-After", "7"), true, true, "http_503_retry_after"},
		{"503 without retry-after", http.StatusServiceUnavailable, headers(), false, false, ""},
		{"x-ratelimit remaining zero", http.StatusOK, headers("X-RateLimit-Remaining", "0"), true, false, "rate_limit_remaining_zero"},
		{"ratelimit remaining zero", http.StatusOK, headers("RateLimit-Remaining", "0"), true, false, "rate_limit_remaining_zero"},
		{"x-ratelimit remaining positive", http.StatusOK, headers("X-RateLimit-Remaining", "42"), false, false, ""},
		{"plain 500", http.StatusInternalServerError, headers(), false, false, ""},
		{"plain 200", http.StatusOK, headers(), false, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := classifyRateLimit(tt.status, tt.header, time.Minute)
			if got.limited != tt.limited || got.discard != tt.discard || got.reason != tt.reason {
				t.Fatalf("classifyRateLimit returned %+v, want limited=%v discard=%v reason=%q", got, tt.limited, tt.discard, tt.reason)
			}
		})
	}
}

func TestRetryAfterParsing(t *testing.T) {
	t.Parallel()
	max := 30 * time.Second
	if got := parseRetryAfter("5", max); got != 5*time.Second {
		t.Fatalf("seconds: got %v", got)
	}
	if got := parseRetryAfter("0", max); got != 0 {
		t.Fatalf("zero: got %v", got)
	}
	if got := parseRetryAfter("-1", max); got != 0 {
		t.Fatalf("negative: got %v", got)
	}
	if got := parseRetryAfter("garbage", max); got != 0 {
		t.Fatalf("garbage: got %v", got)
	}
	if got := parseRetryAfter("3600", max); got != max {
		t.Fatalf("cap: got %v", got)
	}
	when := time.Now().Add(10 * time.Second).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(when, max); got <= 0 || got > 10*time.Second {
		t.Fatalf("http date: got %v", got)
	}
}

func TestRateLimitBackoffAndRecovery(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	l := newTestLimiter(t, clock, RateLimitConfig{
		MaxRate:              100,
		MinRate:              1,
		BackoffFactor:        0.5,
		RecoveryFactor:       2,
		RecoverySuccesses:    3,
		MaxConsecutiveLimits: -1,
	})
	target := "http://example.invalid"
	ctx := t.Context()

	before := l.CurrentRate(target)
	if before != 100 {
		t.Fatalf("initial rate = %v, want 100", before)
	}

	limited, discard, err := limitedResponse().observe(l, target)
	if err != nil || !limited || !discard {
		t.Fatalf("first limited response: limited=%v discard=%v err=%v", limited, discard, err)
	}
	afterFirst := l.CurrentRate(target)
	if afterFirst >= before {
		t.Fatalf("rate did not decrease after a rate limit signal: %v -> %v", before, afterFirst)
	}
	if afterFirst != 50 {
		t.Fatalf("rate after first backoff = %v, want 50", afterFirst)
	}

	// A second signal halves it again.
	if _, _, err := limitedResponse().observe(l, target); err != nil {
		t.Fatalf("second limited response: %v", err)
	}
	if got := l.CurrentRate(target); got != 25 {
		t.Fatalf("rate after second backoff = %v, want 25", got)
	}

	// Pacing is applied after the signal: the aggregated interval is derived
	// from the rate, not from the number of workers.
	waitBefore := len(clock.Waits())
	if err := l.Acquire(ctx, target); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	waits := clock.Waits()
	if len(waits) <= waitBefore {
		t.Fatal("expected Acquire to pace the request after a rate limit signal")
	}
	if intervals := waits[waitBefore:]; intervals[len(intervals)-1] != 40*time.Millisecond {
		t.Fatalf("pacing interval = %v, want 40ms at 25 req/s", intervals[len(intervals)-1])
	}

	// The cooldown from Retry-After was already consumed, so recovery can be
	// driven by consecutive successful responses.
	for range 3 {
		if _, _, err := okResponse().observe(l, target); err != nil {
			t.Fatalf("success response: %v", err)
		}
	}
	recovered := l.CurrentRate(target)
	if recovered <= 25 {
		t.Fatalf("rate did not recover after consecutive successes: %v", recovered)
	}
	if recovered != 50 {
		t.Fatalf("rate after recovery step = %v, want 50", recovered)
	}
	if status, ok := l.StatusFor(target); !ok || status.Limited {
		t.Fatalf("target still marked as limited after recovery: %+v", status)
	}

	// Recovery never exceeds the configured maximum.
	for range 10 {
		for range 3 {
			if _, _, err := okResponse().observe(l, target); err != nil {
				t.Fatalf("success response: %v", err)
			}
		}
	}
	if got := l.CurrentRate(target); got != 100 {
		t.Fatalf("rate exceeded the maximum or did not recover fully: %v", got)
	}

	// Fully recovered: no more pacing until the next signal.
	rate, limitedFlag := l.LimitedRate()
	if limitedFlag || rate != 0 {
		t.Fatalf("limiter still reports limited state: rate=%v limited=%v", rate, limitedFlag)
	}

	// The transitions are recorded and can be replayed.
	var sawLimited, sawRecovered bool
	for _, ev := range l.History() {
		switch ev.Event {
		case RateEventLimited:
			sawLimited = true
		case RateEventRecovered:
			sawRecovered = true
		}
	}
	if !sawLimited || !sawRecovered {
		t.Fatalf("history is missing transitions: limited=%v recovered=%v", sawLimited, sawRecovered)
	}
}

func TestRateLimitRecoveryIsGradual(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	l := newTestLimiter(t, clock, RateLimitConfig{
		MaxRate:              100,
		MinRate:              1,
		BackoffFactor:        0.5,
		RecoveryFactor:       1.5,
		RecoverySuccesses:    1,
		MaxConsecutiveLimits: -1,
	})
	target := "http://example.invalid"

	if _, _, err := limitedResponse().observe(l, target); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	rates := []float64{l.CurrentRate(target)}
	for range 4 {
		if _, _, err := okResponse().observe(l, target); err != nil {
			t.Fatalf("Observe: %v", err)
		}
		rates = append(rates, l.CurrentRate(target))
	}

	steps := 0
	for i := 1; i < len(rates); i++ {
		if rates[i] < rates[i-1] {
			t.Fatalf("recovery went backwards: %v", rates)
		}
		if rates[i] > 100 {
			t.Fatalf("recovery overshoots the maximum: %v", rates)
		}
		if rates[i] > rates[i-1] {
			steps++
		}
	}
	// Recovery must not jump straight back to the maximum.
	if steps < 2 {
		t.Fatalf("recovery jumped to the maximum immediately: %v", rates)
	}
	if rates[len(rates)-1] != 100 {
		t.Fatalf("recovery did not reach the maximum: %v", rates)
	}
}

func TestRateLimitTargetsAreIndependent(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	l := newTestLimiter(t, clock, RateLimitConfig{
		MaxRate:              100,
		MinRate:              1,
		BackoffFactor:        0.5,
		RecoverySuccesses:    2,
		MaxConsecutiveLimits: -1,
	})
	limitedTarget := "http://limited.invalid"
	healthyTarget := "http://healthy.invalid"
	ctx := t.Context()

	if _, _, err := limitedResponse().observe(l, limitedTarget); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if got := l.CurrentRate(limitedTarget); got != 50 {
		t.Fatalf("limited target rate = %v, want 50", got)
	}
	if got := l.CurrentRate(healthyTarget); got != 100 {
		t.Fatalf("healthy target rate = %v, want 100", got)
	}

	// The healthy target is never paced, while the limited one is.
	limitsBefore := len(clock.Waits())
	if err := l.Acquire(ctx, healthyTarget); err != nil {
		t.Fatalf("Acquire healthy: %v", err)
	}
	if len(clock.Waits()) != limitsBefore {
		t.Fatal("healthy target was paced because another target was limited")
	}
	if err := l.Acquire(ctx, limitedTarget); err != nil {
		t.Fatalf("Acquire limited: %v", err)
	}
	if len(clock.Waits()) == limitsBefore {
		t.Fatal("limited target was not paced")
	}

	// Recovery of one target does not touch the other target's state.
	if _, _, err := okResponse().observe(l, healthyTarget); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if got := l.CurrentRate(limitedTarget); got != 50 {
		t.Fatalf("limited target state changed by another target: %v", got)
	}

	statuses := l.Status()
	if len(statuses) != 2 {
		t.Fatalf("expected two target states, got %d", len(statuses))
	}
	byTarget := map[string]RateStatus{}
	for _, st := range statuses {
		byTarget[st.Target] = st
	}
	if !byTarget[limitedTarget].Limited || byTarget[healthyTarget].Limited {
		t.Fatalf("unexpected limited flags: %+v", byTarget)
	}
	if byTarget[limitedTarget].TargetID == byTarget[healthyTarget].TargetID {
		t.Fatal("targets share the same id")
	}
}

func TestRateLimitConcurrentWorkersShareOneBudget(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	l := newTestLimiter(t, clock, RateLimitConfig{
		MaxRate:              100,
		MinRate:              5,
		BackoffFactor:        0.5,
		RecoverySuccesses:    5,
		MaxConsecutiveLimits: -1,
	})
	target := "http://example.invalid"
	ctx := t.Context()

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_ = l.Acquire(ctx, target)
				_, _, _ = limitedResponse().observe(l, target)
				_, _, _ = okResponse().observe(l, target)
				_ = l.CurrentRate(target)
				_ = l.Status()
				_ = l.History()
			}
		}()
	}
	wg.Wait()

	rate := l.CurrentRate(target)
	if rate < 5 || rate > 100 {
		t.Fatalf("rate out of bounds after concurrent updates: %v", rate)
	}
	status, ok := l.StatusFor(target)
	if !ok {
		t.Fatal("missing target state")
	}
	if status.ConsecutiveLimits < 0 || status.ConsecutiveSuccesses < 0 {
		t.Fatalf("negative counters: %+v", status)
	}
}

func TestRateLimitManualRateOverridesAdaptive(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	l := newTestLimiter(t, clock, RateLimitConfig{
		ManualRate:           10,
		MaxRate:              100,
		MinRate:              1,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: 3,
	})
	target := "http://example.invalid"

	for range 5 {
		limited, discard, err := l.Observe(target, http.StatusTooManyRequests, headers())
		if err != nil {
			t.Fatalf("a manual rate must not stop the target: %v", err)
		}
		if limited || discard {
			t.Fatalf("manual rate should not interpret rate limit signals: limited=%v discard=%v", limited, discard)
		}
	}

	if got := l.CurrentRate(target); got != 10 {
		t.Fatalf("manual rate was overridden by the adaptive result: %v", got)
	}
	// The first request is immediate, every following one is spaced by the
	// manual rate.
	for range 2 {
		if err := l.Acquire(t.Context(), target); err != nil {
			t.Fatalf("Acquire: %v", err)
		}
	}
	waits := clock.Waits()
	if len(waits) == 0 || waits[len(waits)-1] != 100*time.Millisecond {
		t.Fatalf("manual rate pacing = %v, want 100ms", waits)
	}
}

func TestRateLimitExhausted(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	l := newTestLimiter(t, clock, RateLimitConfig{
		MaxRate:              100,
		MinRate:              1,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: 3,
	})
	target := "http://example.invalid"

	for i := 1; i <= 2; i++ {
		if _, _, err := limitedResponse().observe(l, target); err != nil {
			t.Fatalf("signal %d: unexpected error %v", i, err)
		}
	}
	if _, _, err := limitedResponse().observe(l, target); !errors.Is(err, ErrRateLimitExhausted) {
		t.Fatalf("expected ErrRateLimitExhausted, got %v", err)
	}
	if !l.AnyExhausted() || !l.AllExhausted() {
		t.Fatal("target was not marked as exhausted")
	}
	if err := l.Acquire(t.Context(), target); !errors.Is(err, ErrRateLimitExhausted) {
		t.Fatalf("Acquire after exhaustion = %v, want ErrRateLimitExhausted", err)
	}

	// A successful response does not resurrect an exhausted target.
	if _, _, err := okResponse().observe(l, target); err != nil {
		t.Fatalf("Observe after exhaustion: %v", err)
	}
	if err := l.Acquire(t.Context(), target); !errors.Is(err, ErrRateLimitExhausted) {
		t.Fatalf("exhausted target resumed: %v", err)
	}
}

func TestRateLimitExhaustionOnlyAffectsItsTarget(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	l := newTestLimiter(t, clock, RateLimitConfig{
		MaxRate:              100,
		MinRate:              1,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: 2,
	})
	bad := "http://bad.invalid"
	good := "http://good.invalid"

	// The healthy target is already known before the other one is written off.
	if _, _, err := okResponse().observe(l, good); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	for range 2 {
		_, _, _ = limitedResponse().observe(l, bad)
	}
	if !l.AnyExhausted() {
		t.Fatal("target was not marked as exhausted")
	}
	if l.AllExhausted() {
		t.Fatal("a single exhausted target must not stop the others")
	}
	if err := l.Acquire(t.Context(), good); err != nil {
		t.Fatalf("healthy target was affected: %v", err)
	}
	if err := l.Acquire(t.Context(), bad); !errors.Is(err, ErrRateLimitExhausted) {
		t.Fatalf("exhausted target accepted requests: %v", err)
	}
}

func TestRateLimitHistoryIsRedactedAndRetriable(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	dir := t.TempDir()
	historyFile := filepath.Join(dir, "missing", "history.jsonl")

	l := newTestLimiter(t, clock, RateLimitConfig{
		MaxRate:              100,
		MinRate:              1,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: -1,
		HistoryFile:          historyFile,
		FlushAttempts:        2,
	})
	target := "http://secret-target.invalid"
	if _, _, err := limitedResponse().observe(l, target); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	pending := l.PendingEvents()
	if pending == 0 {
		t.Fatal("no transitions were recorded")
	}

	// Writing fails, the events are kept for a later attempt.
	if err := l.FlushHistory(); err == nil {
		t.Fatal("expected the flush to fail for a missing directory")
	}
	if got := l.PendingEvents(); got != pending {
		t.Fatalf("pending events changed after a failed flush: %d -> %d", pending, got)
	}
	if l.LastFlushError() == nil {
		t.Fatal("last flush error was not recorded")
	}

	// The directory appears, the retry persists everything.
	if err := os.MkdirAll(filepath.Dir(historyFile), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := l.FlushHistory(); err != nil {
		t.Fatalf("retry flush: %v", err)
	}
	if got := l.PendingEvents(); got != 0 {
		t.Fatalf("pending events after successful flush: %d", got)
	}
	if l.LastFlushError() != nil {
		t.Fatalf("last flush error not cleared: %v", l.LastFlushError())
	}

	f, err := os.Open(historyFile)
	if err != nil {
		t.Fatalf("open history: %v", err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Neither the target address nor any response header value may leak.
		if strings.Contains(line, "secret-target") || strings.Contains(line, "Retry-After") {
			t.Fatalf("history leaks sensitive data: %s", line)
		}
		var ev RateLimitEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("history line is not valid JSON: %v (%s)", err, line)
		}
		if ev.TargetID == "" || ev.Event == "" {
			t.Fatalf("history entry is incomplete: %+v", ev)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan history: %v", err)
	}
	if count == 0 {
		t.Fatal("history file is empty")
	}
}

func TestRateLimitDegradesToFixedRateOnPanic(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	l := newTestLimiter(t, clock, RateLimitConfig{
		MaxRate:              100,
		MinRate:              1,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: -1,
	})
	target := "http://example.invalid"

	// A broken clock simulates a failure inside the rate control module.
	l.now = func() time.Time { panic("boom") }
	// Observing a signal exercises the failing module. The limiter must swallow
	// the failure instead of taking the run down with it.
	if _, _, err := l.Observe(target, http.StatusTooManyRequests, headers()); err != nil {
		t.Fatalf("Observe must not fail when the module panics: %v", err)
	}
	if !l.Degraded() {
		t.Fatal("limiter did not degrade after a failure")
	}

	// The limiter keeps working at a fixed rate.
	l.now = clock.Now
	for range 2 {
		if err := l.Acquire(t.Context(), target); err != nil {
			t.Fatalf("Acquire after degradation: %v", err)
		}
	}
	if len(clock.Waits()) == 0 {
		t.Fatal("degraded limiter stopped pacing")
	}
}

func TestRateLimitConfigNormalization(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   RateLimitConfig
		want RateLimitConfig
	}{
		{
			name: "defaults",
			in:   RateLimitConfig{Adaptive: true},
			want: RateLimitConfig{Adaptive: true, MinRate: 1, MaxRate: 100, BackoffFactor: 0.5, RecoverySuccesses: 10, RecoveryFactor: 1.5, MaxRetryAfter: 30 * time.Second, MaxConsecutiveLimits: 20, FlushAttempts: 3},
		},
		{
			name: "invalid values are replaced",
			in:   RateLimitConfig{Adaptive: true, MinRate: -1, MaxRate: -2, BackoffFactor: 2, RecoverySuccesses: -5, MaxConsecutiveLimits: 0},
			want: RateLimitConfig{Adaptive: true, MinRate: 1, MaxRate: 100, BackoffFactor: 0.5, RecoverySuccesses: 10, RecoveryFactor: 1.5, MaxRetryAfter: 30 * time.Second, MaxConsecutiveLimits: 20, FlushAttempts: 3},
		},
		{
			name: "min bigger than max",
			in:   RateLimitConfig{Adaptive: true, MinRate: 50, MaxRate: 10},
			want: RateLimitConfig{Adaptive: true, MinRate: 50, MaxRate: 50, BackoffFactor: 0.5, RecoverySuccesses: 10, RecoveryFactor: 1.5, MaxRetryAfter: 30 * time.Second, MaxConsecutiveLimits: 20, FlushAttempts: 3},
		},
		{
			name: "manual rate is kept in range",
			in:   RateLimitConfig{ManualRate: 500},
			want: RateLimitConfig{ManualRate: 500, MinRate: 1, MaxRate: 500, BackoffFactor: 0.5, RecoverySuccesses: 10, RecoveryFactor: 1.5, MaxRetryAfter: 30 * time.Second, MaxConsecutiveLimits: 20, FlushAttempts: 3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.Normalized(); got != tt.want {
				t.Fatalf("Normalized() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestWriteRateLimitConfigOnlyWhenActive(t *testing.T) {
	t.Parallel()
	var builder strings.Builder
	if err := WriteRateLimitConfig(&builder, RateLimitConfig{}); err != nil {
		t.Fatalf("WriteRateLimitConfig: %v", err)
	}
	if builder.String() != "" {
		t.Fatalf("disabled rate limiting produced config output: %q", builder.String())
	}

	builder.Reset()
	if err := WriteRateLimitConfig(&builder, RateLimitConfig{Adaptive: true}); err != nil {
		t.Fatalf("WriteRateLimitConfig: %v", err)
	}
	if !strings.Contains(builder.String(), "Adaptive rate") {
		t.Fatalf("active rate limiting produced no config output: %q", builder.String())
	}

	builder.Reset()
	if err := WriteRateLimitConfig(&builder, RateLimitConfig{Adaptive: true, ManualRate: 12.5}); err != nil {
		t.Fatalf("WriteRateLimitConfig: %v", err)
	}
	out := builder.String()
	if !strings.Contains(out, "manual rate overrides it") || !strings.Contains(out, "12.50 req/s") {
		t.Fatalf("manual override is not visible in the config: %q", out)
	}
}

// --- integration tests against a local simulated service ---

type rateLimitServer struct {
	rateLimited atomic.Int64
	requests    atomic.Int64
	// mode decides the response for a request number.
	mode func(n int64) (int, http.Header)
}

func newRateLimitServer(t *testing.T, mode func(n int64) (int, http.Header)) (*httptest.Server, *rateLimitServer) {
	t.Helper()
	state := &rateLimitServer{mode: mode}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := state.requests.Add(1)
		status, header := state.mode(n)
		if status == http.StatusTooManyRequests {
			state.rateLimited.Add(1)
		}
		for k, v := range header {
			w.Header()[k] = v
		}
		w.WriteHeader(status)
		if _, err := fmt.Fprint(w, "body"); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(ts.Close)
	return ts, state
}

func requestTo(t *testing.T, client *HTTPClient, rawURL string) (int, error) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	status, _, _, _, err := client.Request(t.Context(), *u, RequestOptions{})
	return status, err
}

func TestHTTPClientRateLimitedThenRecovers(t *testing.T) {
	t.Parallel()
	// The target sends two rate limit signals and then serves normally.
	ts, state := newRateLimitServer(t, func(n int64) (int, http.Header) {
		if n <= 2 {
			return http.StatusTooManyRequests, headers("Retry-After", "0")
		}
		return http.StatusOK, headers()
	})

	client, err := NewHTTPClient(&HTTPOptions{BasicHTTPOptions: BasicHTTPOptions{RateLimit: RateLimitConfig{
		Adaptive:             true,
		MaxRate:              100,
		MinRate:              1,
		BackoffFactor:        0.5,
		RecoverySuccesses:    2,
		MaxConsecutiveLimits: -1,
	}}}, NewLogger(false))
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	client.rateLimiter.SetQuiet(true)
	target := TargetFromURL(mustURL(t, ts.URL))

	status, err := requestTo(t, client, ts.URL)
	if err != nil {
		t.Fatalf("request after transient rate limiting failed: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if state.rateLimited.Load() != 2 {
		t.Fatalf("server sent %d rate limit responses, want 2", state.rateLimited.Load())
	}

	// Two signals halved the rate twice; the request itself must not have been
	// reported as a result while the target was limiting.
	if got := client.rateLimiter.CurrentRate(target); got != 25 {
		t.Fatalf("rate = %v, want 25", got)
	}

	// Once the target is healthy the rate climbs again.
	for range 4 {
		if _, err := requestTo(t, client, ts.URL); err != nil {
			t.Fatalf("follow up request: %v", err)
		}
	}
	if got := client.rateLimiter.CurrentRate(target); got <= 25 {
		t.Fatalf("rate did not recover after the target stopped limiting: %v", got)
	}
}

func TestHTTPClientStopsOnPersistentRateLimiting(t *testing.T) {
	t.Parallel()
	ts, state := newRateLimitServer(t, func(int64) (int, http.Header) {
		return http.StatusTooManyRequests, headers("Retry-After", "0")
	})

	client, err := NewHTTPClient(&HTTPOptions{BasicHTTPOptions: BasicHTTPOptions{RateLimit: RateLimitConfig{
		Adaptive:             true,
		MaxRate:              250,
		MinRate:              2,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: 3,
	}}}, NewLogger(false))
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	client.rateLimiter.SetQuiet(true)

	status, err := requestTo(t, client, ts.URL)
	if !errors.Is(err, ErrRateLimitExhausted) {
		t.Fatalf("expected ErrRateLimitExhausted, got status=%d err=%v", status, err)
	}
	if got := state.requests.Load(); got != 3 {
		t.Fatalf("server received %d requests, want 3 before giving up", got)
	}

	// Further requests are rejected locally instead of hammering the target.
	if _, err := requestTo(t, client, ts.URL); !errors.Is(err, ErrRateLimitExhausted) {
		t.Fatalf("exhausted target accepted another request: %v", err)
	}
	if got := state.requests.Load(); got != 3 {
		t.Fatalf("exhausted target received %d requests, want 3", got)
	}
}

func TestHTTPClientWithoutRateLimitingIsUnchanged(t *testing.T) {
	t.Parallel()
	// A target that always answers 429: with the feature disabled the response
	// must be handed through untouched, exactly like before the change.
	ts, state := newRateLimitServer(t, func(int64) (int, http.Header) {
		return http.StatusTooManyRequests, headers("Retry-After", "60")
	})

	client, err := NewHTTPClient(&HTTPOptions{}, NewLogger(false))
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if client.RateLimiter() != nil {
		t.Fatal("rate limiter created even though the feature is disabled")
	}

	start := time.Now()
	status, err := requestTo(t, client, ts.URL)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", status)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("disabled limiter waited %v", elapsed)
	}
	if got := state.requests.Load(); got != 1 {
		t.Fatalf("server received %d requests, want exactly 1", got)
	}
}

func TestHTTPClientManualRatePacesRequests(t *testing.T) {
	t.Parallel()
	ts, _ := newRateLimitServer(t, func(int64) (int, http.Header) {
		return http.StatusOK, headers()
	})

	client, err := NewHTTPClient(&HTTPOptions{BasicHTTPOptions: BasicHTTPOptions{RateLimit: RateLimitConfig{ManualRate: 20}}}, NewLogger(false))
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	client.rateLimiter.SetQuiet(true)

	start := time.Now()
	for range 4 {
		if _, err := requestTo(t, client, ts.URL); err != nil {
			t.Fatalf("Request: %v", err)
		}
	}
	// 4 requests at 20 req/s need at least 3 intervals of 50ms.
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("manual rate was not applied, 4 requests took %v", elapsed)
	}
}

func TestHTTPClientRateLimitHeadersStartPacingWithoutDroppingResults(t *testing.T) {
	t.Parallel()
	// A successful response that reports an exhausted budget is still a valid
	// enumeration result; it only starts pacing.
	ts, state := newRateLimitServer(t, func(int64) (int, http.Header) {
		return http.StatusOK, headers("X-RateLimit-Remaining", "0")
	})

	client, err := NewHTTPClient(&HTTPOptions{BasicHTTPOptions: BasicHTTPOptions{RateLimit: RateLimitConfig{
		Adaptive:             true,
		MaxRate:              100,
		MinRate:              1,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: -1,
	}}}, NewLogger(false))
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	client.rateLimiter.SetQuiet(true)

	status, err := requestTo(t, client, ts.URL)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got := state.requests.Load(); got != 1 {
		t.Fatalf("server received %d requests, want 1 (result must not be retried)", got)
	}
	target := TargetFromURL(mustURL(t, ts.URL))
	if got := client.rateLimiter.CurrentRate(target); got != 50 {
		t.Fatalf("rate = %v, want 50 after the rate limit header", got)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestTargetKeyAggregatesPathsPerHost(t *testing.T) {
	t.Parallel()
	a := mustURL(t, "http://example.invalid/a")
	b := mustURL(t, "http://example.invalid/deep/path?q=1")
	c := mustURL(t, "http://other.invalid/a")
	if TargetFromURL(a) != TargetFromURL(b) {
		t.Fatal("paths of the same host must share one rate state")
	}
	if TargetFromURL(a) == TargetFromURL(c) {
		t.Fatal("different hosts must not share a rate state")
	}
	if TargetKey(a, "") == TargetKey(a, "vhost.example.invalid") {
		t.Fatal("virtual hosts must get their own rate state")
	}
}

func TestRateLimitManyPathsShareOneBudgetPerTarget(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	l := newTestLimiter(t, clock, RateLimitConfig{
		MaxRate:              10,
		MinRate:              1,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: -1,
	})
	ctx := t.Context()
	target := TargetFromURL(mustURL(t, "http://example.invalid/deep/path"))
	// Trigger pacing for the host.
	if _, _, err := limitedResponse().observe(l, target); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				if err := l.Acquire(ctx, target); err != nil {
					t.Errorf("Acquire: %v", err)
				}
			}
		}()
	}
	wg.Wait()

	// 80 acquisitions share one aggregate budget of at most 5 req/s. The fake
	// clock only advances by the waits, so the total wait has to grow with the
	// number of acquisitions instead of being constant per goroutine.
	waits := clock.Waits()
	if len(waits) < 70 {
		t.Fatalf("only %d of 80 acquisitions were paced, budget is not shared", len(waits))
	}
	last := waits[len(waits)-1]
	if last > 400*time.Millisecond {
		t.Fatalf("pacing interval = %v, expected the aggregated rate to be respected", last)
	}
}

func TestHTTPClientMultipleTargetsAreIsolated(t *testing.T) {
	t.Parallel()
	limitedServer, limitedState := newRateLimitServer(t, func(int64) (int, http.Header) {
		return http.StatusTooManyRequests, headers()
	})
	healthyServer, healthyState := newRateLimitServer(t, func(int64) (int, http.Header) {
		return http.StatusOK, headers()
	})

	client, err := NewHTTPClient(&HTTPOptions{BasicHTTPOptions: BasicHTTPOptions{RateLimit: RateLimitConfig{
		Adaptive:             true,
		MaxRate:              50,
		MinRate:              1,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: 2,
	}}}, NewLogger(false))
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	client.rateLimiter.SetQuiet(true)

	// Write off the limited target.
	if _, err := requestTo(t, client, limitedServer.URL); !errors.Is(err, ErrRateLimitExhausted) {
		t.Fatalf("expected ErrRateLimitExhausted, got %v", err)
	}
	if got := limitedState.requests.Load(); got != 2 {
		t.Fatalf("limited target received %d requests, want 2", got)
	}

	// The healthy target keeps answering at full speed.
	start := time.Now()
	for range 10 {
		status, err := requestTo(t, client, healthyServer.URL)
		if err != nil || status != http.StatusOK {
			t.Fatalf("healthy target affected by the limited one: status=%d err=%v", status, err)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("healthy target was slowed down by the limited one: %v", elapsed)
	}
	if got := healthyState.requests.Load(); got != 10 {
		t.Fatalf("healthy target received %d requests, want 10", got)
	}
	if !client.rateLimiter.AnyExhausted() || client.rateLimiter.AllExhausted() {
		t.Fatal("unexpected exhaustion state with one healthy target")
	}
}

func TestRateLimitRetryAfterCooldown(t *testing.T) {
	t.Parallel()
	clock := newFakeClock()
	l := newTestLimiter(t, clock, RateLimitConfig{
		MaxRate:              100,
		MinRate:              1,
		BackoffFactor:        0.5,
		MaxConsecutiveLimits: -1,
	})
	target := "http://example.invalid"

	if _, _, err := limitedResponseWithRetryAfter(2).observe(l, target); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	// The first Acquire right after the signal waits for the whole cooldown.
	if err := l.Acquire(t.Context(), target); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	waits := clock.Waits()
	if len(waits) == 0 || waits[0] < 2*time.Second {
		t.Fatalf("Retry-After was not honoured: %v", waits)
	}
}
