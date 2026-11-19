package libgobuster

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultRateMin             = 1.0
	defaultRateMax             = 100.0
	defaultRateBackoffFactor   = 0.5
	defaultRateRecoverySuccess = 10
	defaultRateRecoveryFactor  = 1.5
	defaultRateMaxConsecutive  = 20
	defaultRateMaxRetryAfter   = 30 * time.Second
	defaultRateFlushAttempts   = 3
	defaultRateFlushRetryDelay = 50 * time.Millisecond
	maxRateLimitHistory        = 4096
)

// RateLimitEvent names the state transitions that are recorded for a target.
const (
	RateEventLimited   = "limited"
	RateEventBackoff   = "backoff"
	RateEventAdjusted  = "adjusted"
	RateEventRecovered = "recovered"
	RateEventExhausted = "exhausted"
)

// RateLimitConfig controls the adaptive rate limiting. All rates are requests
// per second and apply per target.
type RateLimitConfig struct {
	// Adaptive enables the adaptive rate limiter. When it is disabled and no
	// manual rate is set the limiter does not exist at all.
	Adaptive bool
	// ManualRate, when > 0, pins the request rate and disables the adaptive
	// adjustments. It always wins over the adaptive result.
	ManualRate float64
	// MinRate is the lowest rate the adaptive limiter backs off to.
	MinRate float64
	// MaxRate is the highest rate the adaptive limiter recovers to.
	MaxRate float64
	// BackoffFactor multiplies the current rate after a rate limit signal.
	BackoffFactor float64
	// RecoverySuccesses is the number of consecutive non-limited responses
	// required before the rate is increased again.
	RecoverySuccesses int
	// RecoveryFactor multiplies the current rate for every recovery step.
	RecoveryFactor float64
	// MaxRetryAfter caps how long a Retry-After signal may pause a target.
	MaxRetryAfter time.Duration
	// MaxConsecutiveLimits stops the target after that many consecutive rate
	// limit signals. Zero uses the default, a negative value disables stopping.
	MaxConsecutiveLimits int
	// HistoryFile, when set, receives the observed state transitions as JSON
	// lines. It never contains target addresses or response header values.
	HistoryFile string
	// FlushAttempts is the number of attempts made to persist the history.
	FlushAttempts int
}

// Active reports whether the configuration has any effect at all.
func (c RateLimitConfig) Active() bool {
	return c.Adaptive || c.ManualRate > 0
}

// Normalized returns a copy of the config with defaults filled in and values
// clamped into a usable range. Invalid values are replaced instead of failing
// so the rate limiter can always degrade to a fixed rate.
func (c RateLimitConfig) Normalized() RateLimitConfig {
	isBad := func(v float64) bool {
		return math.IsNaN(v) || math.IsInf(v, 0)
	}

	// Asking for a history file only makes sense when the transitions are
	// observed, so it implies adaptive rate limiting.
	if c.HistoryFile != "" {
		c.Adaptive = true
	}
	if c.ManualRate < 0 || isBad(c.ManualRate) {
		c.ManualRate = 0
	}
	if c.MinRate <= 0 || isBad(c.MinRate) {
		c.MinRate = defaultRateMin
	}
	if c.MaxRate <= 0 || isBad(c.MaxRate) {
		c.MaxRate = defaultRateMax
	}
	if c.MaxRate < c.MinRate {
		c.MaxRate = c.MinRate
	}
	if c.BackoffFactor <= 0 || c.BackoffFactor >= 1 || isBad(c.BackoffFactor) {
		c.BackoffFactor = defaultRateBackoffFactor
	}
	if c.RecoveryFactor <= 1 || isBad(c.RecoveryFactor) {
		c.RecoveryFactor = defaultRateRecoveryFactor
	}
	if c.RecoverySuccesses <= 0 {
		c.RecoverySuccesses = defaultRateRecoverySuccess
	}
	if c.MaxRetryAfter <= 0 {
		c.MaxRetryAfter = defaultRateMaxRetryAfter
	}
	if c.MaxConsecutiveLimits == 0 {
		c.MaxConsecutiveLimits = defaultRateMaxConsecutive
	}
	if c.FlushAttempts <= 0 {
		c.FlushAttempts = defaultRateFlushAttempts
	}
	if c.ManualRate > 0 {
		if c.ManualRate < c.MinRate {
			c.MinRate = c.ManualRate
		}
		if c.ManualRate > c.MaxRate {
			c.MaxRate = c.ManualRate
		}
	}
	return c
}

// initialRate is the rate used before any signal was observed.
func (c RateLimitConfig) initialRate() float64 {
	if c.ManualRate > 0 {
		return c.ManualRate
	}
	return c.MaxRate
}

// RateLimitEvent is a single recorded rate state transition.
type RateLimitEvent struct {
	Time         time.Time `json:"time"`
	TargetID     string    `json:"target_id"`
	Event        string    `json:"event"`
	Reason       string    `json:"reason,omitempty"`
	PreviousRate float64   `json:"previous_rate"`
	Rate         float64   `json:"rate"`
}

// RateStatus is a point in time snapshot of one target's rate state.
type RateStatus struct {
	TargetID             string  `json:"target_id"`
	Target               string  `json:"target"`
	Rate                 float64 `json:"rate"`
	Limited              bool    `json:"limited"`
	Exhausted            bool    `json:"exhausted"`
	ConsecutiveLimits    int     `json:"consecutive_limits"`
	ConsecutiveSuccesses int     `json:"consecutive_successes"`
}

type rateLimitState struct {
	mu                   sync.Mutex
	id                   string
	rate                 float64
	limited              bool
	exhausted            bool
	consecutiveLimits    int
	consecutiveSuccesses int
	nextAllowed          time.Time
}

// RateLimiter paces requests per target and adapts the pace based on explicit
// rate limit signals in the target's responses. A single RateLimiter can be
// shared by any number of clients and targets; every target has its own state.
type RateLimiter struct {
	cfg      RateLimitConfig
	logger   *Logger
	quiet    atomic.Bool
	degraded atomic.Bool

	// now and sleep are replaceable so tests can drive the limiter without
	// waiting for wall clock time.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error

	mu      sync.RWMutex
	targets map[string]*rateLimitState
	order   []string
	nextID  int

	pendingMu sync.Mutex
	pending   []RateLimitEvent
	history   []RateLimitEvent

	flushMu      sync.Mutex
	lastFlushErr error

	manualWarned sync.Once
}

// NewRateLimiter returns a RateLimiter for the given configuration. It returns
// nil when the configuration is inactive, which means request pacing is
// completely disabled. Invalid values are normalized so the limiter always
// remains usable.
func NewRateLimiter(cfg RateLimitConfig, logger *Logger) *RateLimiter {
	normalized := cfg.Normalized()
	if !normalized.Active() {
		return nil
	}
	l := &RateLimiter{
		cfg:     normalized,
		logger:  logger,
		targets: make(map[string]*rateLimitState),
		now:     time.Now,
		sleep:   sleepContext,
	}
	return l
}

// SetQuiet suppresses the log output of the limiter. State transitions are
// still recorded and can be retrieved via Status and History.
func (l *RateLimiter) SetQuiet(quiet bool) {
	if l == nil {
		return
	}
	l.quiet.Store(quiet)
}

// WriteRateLimitConfig writes the active rate limiting options as human
// readable rows. Lines are only emitted when the corresponding option is
// active, so the output of a run without rate limiting is unchanged.
func WriteRateLimitConfig(tw io.Writer, cfg RateLimitConfig) error {
	c := cfg.Normalized()
	if !c.Active() {
		return nil
	}
	if c.Adaptive {
		if c.ManualRate > 0 {
			if _, err := fmt.Fprintf(tw, "[+] Adaptive rate:\toff (manual rate overrides it)\n"); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(tw, "[+] Adaptive rate:\ton (%.2f - %.2f req/s, recovers after %d successes)\n", c.MinRate, c.MaxRate, c.RecoverySuccesses); err != nil {
			return err
		}
	}
	if c.ManualRate > 0 {
		if _, err := fmt.Fprintf(tw, "[+] Rate limit:\t%.2f req/s\n", c.ManualRate); err != nil {
			return err
		}
	}
	if c.HistoryFile != "" {
		if _, err := fmt.Fprintf(tw, "[+] Rate history:\t%s\n", c.HistoryFile); err != nil {
			return err
		}
	}
	return nil
}

// TargetFromURL builds the aggregation key for a request. All paths on the
// same scheme and host share one rate state. A per-request Host (used by VHOST
// mode) is treated as a separate target.
func TargetFromURL(u *url.URL) string {
	return TargetKey(u, "")
}

// TargetKey builds the aggregation key for a request to u. An empty host is
// ignored; otherwise it is appended so virtual hosts are tracked separately.
func TargetKey(u *url.URL, host string) string {
	if u == nil {
		return strings.ToLower(host)
	}
	key := strings.ToLower(u.Scheme + "://" + u.Host)
	if host != "" {
		key += "|" + strings.ToLower(host)
	}
	return key
}

func (l *RateLimiter) logf(level MessageLevel, format string, args ...any) {
	if l == nil || l.logger == nil || l.quiet.Load() {
		return
	}
	switch level {
	case LevelDebug:
		l.logger.Debugf(format, args...)
	case LevelInfo:
		l.logger.Infof(format, args...)
	case LevelWarn:
		l.logger.Warnf(format, args...)
	case LevelError:
		l.logger.Errorf(format, args...)
	}
}

func (l *RateLimiter) state(target string) *rateLimitState {
	l.mu.RLock()
	st, ok := l.targets[target]
	l.mu.RUnlock()
	if ok {
		return st
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	// Another goroutine may have created it while we were waiting.
	if st, ok = l.targets[target]; ok {
		return st
	}
	l.nextID++
	st = &rateLimitState{
		id:   fmt.Sprintf("target-%d", l.nextID),
		rate: l.cfg.initialRate(),
	}
	l.targets[target] = st
	l.order = append(l.order, target)
	return st
}

// Acquire blocks until a request to target may be issued. The wait is derived
// from the aggregated rate of the target, so concurrent workers share one
// pacing budget instead of each pacing independently.
func (l *RateLimiter) Acquire(ctx context.Context, target string) (err error) {
	if l == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			l.degrade(fmt.Errorf("panic in rate limiter acquire: %v", r))
			err = nil
		}
	}()

	st := l.state(target)

	st.mu.Lock()
	if st.exhausted {
		st.mu.Unlock()
		return ErrRateLimitExhausted
	}
	rate := st.rate
	if l.degraded.Load() {
		rate = l.fixedRate()
	}
	// Before any rate limit signal the target is not paced at all. Pacing only
	// starts once the target actually asked for it, which keeps the behaviour
	// identical to a run without adaptive rate limiting until then.
	paced := false
	switch {
	case l.degraded.Load():
		paced = true
	case l.cfg.ManualRate > 0:
		paced = true
	case l.adaptiveActive():
		paced = st.limited || rate < l.cfg.MaxRate
	}
	var wait time.Duration
	if rate > 0 && paced {
		interval := time.Duration(float64(time.Second) / rate)
		now := l.now()
		next := st.nextAllowed
		if next.Before(now) {
			next = now
		}
		wait = next.Sub(now)
		st.nextAllowed = next.Add(interval)
	}
	st.mu.Unlock()

	if l.cfg.ManualRate > 0 && l.cfg.Adaptive {
		l.manualWarned.Do(func() {
			l.logf(LevelWarn, "manual rate %.2f req/s is set, adaptive rate limiting is overridden", l.cfg.ManualRate)
		})
	}

	if wait <= 0 {
		return nil
	}
	return l.sleep(ctx, wait)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// fixedRate is the rate the limiter falls back to when it is degraded.
func (l *RateLimiter) fixedRate() float64 {
	if l.cfg.ManualRate > 0 {
		return l.cfg.ManualRate
	}
	return l.cfg.initialRate()
}

// Observe feeds one response back into the rate limiter. It reports whether the
// response carried a rate limit signal (limited) and whether the response must
// be discarded instead of being used as an enumeration result (discard).
// Only explicit signals (status codes and rate limit headers) are used, never
// request durations. It also returns ErrRateLimitExhausted once the target is
// written off.
func (l *RateLimiter) Observe(target string, statusCode int, header http.Header) (limited, discard bool, err error) {
	if l == nil {
		return false, false, nil
	}
	defer func() {
		if r := recover(); r != nil {
			l.degrade(fmt.Errorf("panic in rate limiter observe: %v", r))
			limited = false
			discard = false
			err = nil
		}
	}()

	signal := classifyRateLimit(statusCode, header, l.cfg.MaxRetryAfter)
	if !l.adaptiveActive() {
		// A manual rate always wins over the adaptive result. Signals are not
		// interpreted at all, so the run behaves like a fixed rate run.
		return false, false, nil
	}
	st := l.state(target)
	events, exhausted := l.observe(st, signal)
	l.record(events)
	// A response that is merely flagged as limited (for example a successful
	// response with an exhausted rate limit budget) is still a valid result. It
	// only starts pacing. Only responses that cannot be used for enumeration
	// are retried.
	discard = signal.discard
	if exhausted {
		return signal.limited, discard, ErrRateLimitExhausted
	}
	return signal.limited, discard, nil
}

// adaptiveActive reports whether rate state is currently derived from
// responses. A manual rate always wins over the adaptive result.
func (l *RateLimiter) adaptiveActive() bool {
	return l.cfg.Adaptive && l.cfg.ManualRate <= 0
}

// rateSignal is an explicit rate limit indication found in a response.
type rateSignal struct {
	limited    bool
	discard    bool
	reason     string
	retryAfter time.Duration
}

func (l *RateLimiter) observe(st *rateLimitState, signal rateSignal) ([]RateLimitEvent, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	var events []RateLimitEvent
	now := l.now()
	previous := st.rate
	// A manual rate always wins over the adaptive result: signals are still
	// recorded so they stay observable, but the rate is never changed.
	adaptive := !l.degraded.Load() && l.adaptiveActive()
	retryAfter := signal.retryAfter

	if signal.limited {
		st.consecutiveLimits++
		st.consecutiveSuccesses = 0

		wasLimited := st.limited
		st.limited = true

		if adaptive && previous > 0 {
			newRate := previous * l.cfg.BackoffFactor
			if newRate < l.cfg.MinRate {
				newRate = l.cfg.MinRate
			}
			if newRate != previous {
				st.rate = newRate
				events = append(events, l.event(st, RateEventBackoff, signal.reason, previous, newRate, now))
			}
		}
		if !wasLimited {
			events = append(events, l.event(st, RateEventLimited, signal.reason, previous, st.rate, now))
		}

		exhausted := false
		if adaptive && l.cfg.MaxConsecutiveLimits > 0 && st.consecutiveLimits >= l.cfg.MaxConsecutiveLimits && !st.exhausted {
			st.exhausted = true
			exhausted = true
			events = append(events, l.event(st, RateEventExhausted, signal.reason, previous, st.rate, now))
		}

		if retryAfter <= 0 && st.rate > 0 {
			retryAfter = time.Duration(float64(time.Second) / st.rate)
		}
		if retryAfter > 0 {
			if next := now.Add(retryAfter); next.After(st.nextAllowed) {
				st.nextAllowed = next
			}
		}
		return events, exhausted
	}

	st.consecutiveLimits = 0
	if !st.limited && st.rate >= l.cfg.MaxRate {
		st.consecutiveSuccesses = 0
		return nil, false
	}

	st.consecutiveSuccesses++
	if st.consecutiveSuccesses < l.cfg.RecoverySuccesses {
		return nil, false
	}
	st.consecutiveSuccesses = 0
	wasLimited := st.limited
	st.limited = false
	if adaptive && previous > 0 {
		newRate := previous * l.cfg.RecoveryFactor
		if newRate > l.cfg.MaxRate {
			newRate = l.cfg.MaxRate
		}
		st.rate = newRate
	}
	eventName := RateEventAdjusted
	if wasLimited {
		eventName = RateEventRecovered
	}
	events = append(events, l.event(st, eventName, "", previous, st.rate, now))
	return events, false
}

func (l *RateLimiter) event(st *rateLimitState, name, reason string, previous, rate float64, now time.Time) RateLimitEvent {
	return RateLimitEvent{
		Time:         now,
		TargetID:     st.id,
		Event:        name,
		Reason:       reason,
		PreviousRate: previous,
		Rate:         rate,
	}
}

func (l *RateLimiter) record(events []RateLimitEvent) {
	if len(events) == 0 {
		return
	}

	l.pendingMu.Lock()
	l.pending = append(l.pending, events...)
	l.history = append(l.history, events...)
	if len(l.history) > maxRateLimitHistory {
		l.history = l.history[len(l.history)-maxRateLimitHistory:]
	}
	l.pendingMu.Unlock()

	for _, ev := range events {
		switch ev.Event {
		case RateEventLimited:
			l.logf(LevelWarn, "%s is rate limiting requests (%s): reducing request rate %.2f -> %.2f req/s", ev.TargetID, ev.Reason, ev.PreviousRate, ev.Rate)
		case RateEventBackoff:
			l.logf(LevelDebug, "%s backed off request rate %.2f -> %.2f req/s", ev.TargetID, ev.PreviousRate, ev.Rate)
		case RateEventRecovered:
			l.logf(LevelInfo, "%s recovered: increasing request rate %.2f -> %.2f req/s", ev.TargetID, ev.PreviousRate, ev.Rate)
		case RateEventAdjusted:
			l.logf(LevelDebug, "%s increased request rate %.2f -> %.2f req/s", ev.TargetID, ev.PreviousRate, ev.Rate)
		case RateEventExhausted:
			l.logf(LevelError, "%s kept rate limiting for %d consecutive responses (%s): stopping enumeration for this target", ev.TargetID, l.cfg.MaxConsecutiveLimits, ev.Reason)
		}
	}
}

func (l *RateLimiter) degrade(cause error) {
	if l == nil {
		return
	}
	if l.degraded.CompareAndSwap(false, true) {
		l.logf(LevelWarn, "rate limiting is degraded to a fixed rate of %.2f req/s: %v", l.fixedRate(), cause)
	}
}

// Degraded reports whether the limiter fell back to a fixed rate.
func (l *RateLimiter) Degraded() bool {
	return l != nil && l.degraded.Load()
}

// HistoryFile returns the configured history file, or an empty string.
func (l *RateLimiter) HistoryFile() string {
	if l == nil {
		return ""
	}
	return l.cfg.HistoryFile
}

// Status returns a snapshot of all target states in creation order.
func (l *RateLimiter) Status() []RateStatus {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	order := append([]string(nil), l.order...)
	l.mu.RUnlock()

	statuses := make([]RateStatus, 0, len(order))
	for _, target := range order {
		if st, ok := l.StatusFor(target); ok {
			statuses = append(statuses, st)
		}
	}
	return statuses
}

// StatusFor returns the current state of one target.
func (l *RateLimiter) StatusFor(target string) (RateStatus, bool) {
	if l == nil {
		return RateStatus{}, false
	}
	l.mu.RLock()
	st, ok := l.targets[target]
	l.mu.RUnlock()
	if !ok {
		return RateStatus{}, false
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	return RateStatus{
		TargetID:             st.id,
		Target:               target,
		Rate:                 st.rate,
		Limited:              st.limited,
		Exhausted:            st.exhausted,
		ConsecutiveLimits:    st.consecutiveLimits,
		ConsecutiveSuccesses: st.consecutiveSuccesses,
	}, true
}

// CurrentRate returns the rate currently used for one target. Targets that
// have not sent any request yet report the initial rate.
func (l *RateLimiter) CurrentRate(target string) float64 {
	if l == nil {
		return 0
	}
	if st, ok := l.StatusFor(target); ok {
		return st.Rate
	}
	return l.cfg.initialRate()
}

// LimitedRate reports whether any target is currently limited and returns the
// lowest rate among the limited targets. It is used for the progress display
// and does not expose target addresses.
func (l *RateLimiter) LimitedRate() (float64, bool) {
	if l == nil {
		return 0, false
	}
	limited := false
	rate := 0.0
	for _, st := range l.Status() {
		if !st.Limited {
			continue
		}
		if !limited || st.Rate < rate {
			rate = st.Rate
		}
		limited = true
	}
	return rate, limited
}

// AnyExhausted reports whether at least one target was written off.
func (l *RateLimiter) AnyExhausted() bool {
	if l == nil {
		return false
	}
	for _, st := range l.Status() {
		if st.Exhausted {
			return true
		}
	}
	return false
}

// AllExhausted reports whether every known target was written off.
func (l *RateLimiter) AllExhausted() bool {
	if l == nil {
		return false
	}
	statuses := l.Status()
	if len(statuses) == 0 {
		return false
	}
	for _, st := range statuses {
		if !st.Exhausted {
			return false
		}
	}
	return true
}

// History returns a copy of all recorded rate state transitions.
func (l *RateLimiter) History() []RateLimitEvent {
	if l == nil {
		return nil
	}
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	return append([]RateLimitEvent(nil), l.history...)
}

// PendingEvents returns the number of transitions that have not been persisted
// to the history file yet.
func (l *RateLimiter) PendingEvents() int {
	if l == nil {
		return 0
	}
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	return len(l.pending)
}

// LastFlushError returns the error of the last failed history flush.
func (l *RateLimiter) LastFlushError() error {
	if l == nil {
		return nil
	}
	l.flushMu.Lock()
	defer l.flushMu.Unlock()
	return l.lastFlushErr
}

// FlushHistory persists all pending transitions to HistoryFile. Events are
// kept in memory when writing fails so a later call can retry them. Failing to
// write never affects request processing.
func (l *RateLimiter) FlushHistory() error {
	if l == nil || l.cfg.HistoryFile == "" {
		return nil
	}
	l.flushMu.Lock()
	defer l.flushMu.Unlock()

	l.pendingMu.Lock()
	events := append([]RateLimitEvent(nil), l.pending...)
	l.pendingMu.Unlock()
	if len(events) == 0 {
		l.lastFlushErr = nil
		return nil
	}

	var lastErr error
	for attempt := range l.cfg.FlushAttempts {
		lastErr = l.writeHistory(events)
		if lastErr == nil {
			l.dropPending(len(events))
			l.lastFlushErr = nil
			return nil
		}
		if attempt < l.cfg.FlushAttempts-1 {
			time.Sleep(defaultRateFlushRetryDelay * time.Duration(attempt+1))
		}
	}

	l.lastFlushErr = fmt.Errorf("could not write rate limit history to %q: %w", l.cfg.HistoryFile, lastErr)
	return l.lastFlushErr
}

func (l *RateLimiter) writeHistory(events []RateLimitEvent) error {
	f, err := os.OpenFile(l.cfg.HistoryFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, ev := range events {
		line, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return nil
}

func (l *RateLimiter) dropPending(n int) {
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	if n >= len(l.pending) {
		l.pending = nil
		return
	}
	l.pending = append([]RateLimitEvent(nil), l.pending[n:]...)
}

// classifyRateLimit inspects a response for explicit rate limit signals. It
// never looks at timing.
func classifyRateLimit(statusCode int, header http.Header, maxRetryAfter time.Duration) rateSignal {
	retryAfter := parseRetryAfter(header.Get("Retry-After"), maxRetryAfter)

	switch {
	case statusCode == http.StatusTooManyRequests:
		return rateSignal{limited: true, discard: true, reason: "http_429", retryAfter: retryAfter}
	case remainsZero(header.Get("X-RateLimit-Remaining")) || remainsZero(header.Get("RateLimit-Remaining")):
		return rateSignal{limited: true, reason: "rate_limit_remaining_zero", retryAfter: retryAfter}
	case statusCode == http.StatusServiceUnavailable && header.Get("Retry-After") != "":
		return rateSignal{limited: true, discard: true, reason: "http_503_retry_after", retryAfter: retryAfter}
	default:
		return rateSignal{}
	}
}

func remainsZero(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	n, err := strconv.Atoi(value)
	return err == nil && n <= 0
}

func parseRetryAfter(value string, max time.Duration) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	var delay time.Duration
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		delay = time.Duration(seconds) * time.Second
	} else if when, err := http.ParseTime(value); err == nil {
		delay = time.Until(when)
		if delay <= 0 {
			return 0
		}
	} else {
		return 0
	}
	if delay > max {
		delay = max
	}
	return delay
}
