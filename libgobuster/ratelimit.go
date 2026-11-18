package libgobuster

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	// adaptiveSuccessThreshold is the number of consecutive successful
	// responses required before the adaptive controller increases the rate
	adaptiveSuccessThreshold = 25
	// adaptiveRecoverDelay is the minimum time after a decrease before the
	// adaptive controller is allowed to increase the rate again
	adaptiveRecoverDelay = 3 * time.Second
	// adaptiveDecreaseFactor is the multiplicative decrease applied on
	// throttling signals (429/503/connection reset)
	adaptiveDecreaseFactor = 0.5
)

// RateAdjustEvent describes a single rate adjustment for audit logging
type RateAdjustEvent struct {
	Time    time.Time
	Scope   string
	OldRate float64
	NewRate float64
	Reason  string
}

// String returns a printable representation of the event
func (e RateAdjustEvent) String() string {
	return fmt.Sprintf("%s scope=%s rate %.2f -> %.2f req/s reason=%q",
		e.Time.Format(time.RFC3339), e.Scope, e.OldRate, e.NewRate, e.Reason)
}

// RateLimiter is a reservation based token bucket limiter. Waiters block on
// their own timers, so no single goroutine pool is stalled as a whole. The
// rate can be changed at runtime; waiting goroutines are woken up and
// re-reserve against the new rate, so they can never be parked forever.
type RateLimiter struct {
	mu       sync.Mutex
	scope    string
	maxRate  float64
	minRate  float64
	rate     float64
	next     time.Time
	changeCh chan struct{}
	adaptive bool
	onEvent  func(RateAdjustEvent)

	successes    int
	lastDecrease time.Time
}

// NewRateLimiter creates a limiter. maxRate is the configured ceiling in
// requests per second and must be > 0. minRate is the lower bound used by
// the adaptive controller.
func NewRateLimiter(scope string, maxRate, minRate float64, adaptive bool, onEvent func(RateAdjustEvent)) *RateLimiter {
	if minRate <= 0 {
		minRate = 1
	}
	if maxRate < minRate {
		maxRate = minRate
	}
	return &RateLimiter{
		scope:    scope,
		maxRate:  maxRate,
		minRate:  minRate,
		rate:     maxRate,
		changeCh: make(chan struct{}),
		adaptive: adaptive,
		onEvent:  onEvent,
	}
}

// reserve claims the next token and returns the time to wait for it along
// with a channel that is closed whenever the rate changes.
func (l *RateLimiter) reserve() (time.Duration, <-chan struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	interval := time.Duration(float64(time.Second) / l.rate)
	start := now
	if l.next.After(start) {
		start = l.next
	}
	l.next = start.Add(interval)
	return start.Sub(now), l.changeCh
}

// Wait blocks until a token is available, the context is canceled or the
// rate changes (in which case it re-reserves against the new rate).
func (l *RateLimiter) Wait(ctx context.Context) error {
	for {
		d, changed := l.reserve()
		if d <= 0 {
			return nil
		}
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-changed:
			// rate was adjusted, re-reserve against the new rate
			timer.Stop()
		case <-timer.C:
			return nil
		}
	}
}

// setRateLocked updates the rate and wakes up all waiters. Caller must hold l.mu.
func (l *RateLimiter) setRateLocked(newRate float64, reason string) {
	if newRate < l.minRate {
		newRate = l.minRate
	}
	if newRate > l.maxRate {
		newRate = l.maxRate
	}
	if newRate == l.rate {
		return
	}
	old := l.rate
	l.rate = newRate
	// allow immediate re-reservation so waiters are never stuck behind a
	// reservation made under the old rate
	l.next = time.Now()
	close(l.changeCh)
	l.changeCh = make(chan struct{})
	if l.onEvent != nil {
		l.onEvent(RateAdjustEvent{
			Time:    time.Now(),
			Scope:   l.scope,
			OldRate: old,
			NewRate: newRate,
			Reason:  reason,
		})
	}
}

// SetRate changes the current rate and the configured ceiling.
func (l *RateLimiter) SetRate(newRate float64, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if newRate < l.minRate {
		newRate = l.minRate
	}
	l.maxRate = newRate
	l.setRateLocked(newRate, reason)
}

// CurrentRate returns the current effective rate.
func (l *RateLimiter) CurrentRate() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rate
}

// Feedback feeds the adaptive AIMD controller. A throttled signal (HTTP 429,
// 503 or connection reset) halves the rate; consecutive successful responses
// slowly increase it again towards the configured maximum.
func (l *RateLimiter) Feedback(throttled bool) {
	if !l.adaptive {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if throttled {
		l.successes = 0
		l.lastDecrease = time.Now()
		l.setRateLocked(l.rate*adaptiveDecreaseFactor, "target throttled the request (429/503/connection reset), decreasing rate")
		return
	}
	l.successes++
	if l.successes >= adaptiveSuccessThreshold && time.Since(l.lastDecrease) >= adaptiveRecoverDelay {
		l.successes = 0
		step := l.maxRate * 0.05
		if step < 1 {
			step = 1
		}
		l.setRateLocked(l.rate+step, "target recovered, slowly increasing rate")
	}
}

// RateLimitGroup combines a global limiter with per-target limiters. A
// request has to pass both, so the stricter of the two always wins.
type RateLimitGroup struct {
	global        *RateLimiter
	perTargetRate float64
	minRate       float64
	adaptive      bool
	onEvent       func(RateAdjustEvent)

	mu      sync.Mutex
	targets map[string]*RateLimiter
}

// NewRateLimitGroup creates a group. A rate <= 0 disables the respective
// limiter. If both are disabled and adaptive is false, nil is returned.
func NewRateLimitGroup(globalRate, perTargetRate, minRate float64, adaptive bool) (*RateLimitGroup, error) {
	if globalRate <= 0 && perTargetRate <= 0 {
		if adaptive {
			return nil, fmt.Errorf("adaptive rate control requires --rate-limit or --rate-limit-per-target to be set")
		}
		return nil, nil // nolint:nilnil
	}
	if minRate <= 0 {
		minRate = 1
	}
	if globalRate > 0 && globalRate < minRate {
		return nil, fmt.Errorf("rate-limit (%.2f) must be >= rate-min (%.2f)", globalRate, minRate)
	}
	if perTargetRate > 0 && perTargetRate < minRate {
		return nil, fmt.Errorf("rate-limit-per-target (%.2f) must be >= rate-min (%.2f)", perTargetRate, minRate)
	}
	g := &RateLimitGroup{
		perTargetRate: perTargetRate,
		minRate:       minRate,
		adaptive:      adaptive,
		targets:       make(map[string]*RateLimiter),
	}
	if globalRate > 0 {
		g.global = NewRateLimiter("global", globalRate, minRate, adaptive, nil)
	}
	return g, nil
}

// SetEventHandler registers the callback invoked for every rate adjustment.
func (g *RateLimitGroup) SetEventHandler(onEvent func(RateAdjustEvent)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.onEvent = onEvent
	if g.global != nil {
		g.global.onEvent = onEvent
	}
	for _, l := range g.targets {
		l.onEvent = onEvent
	}
}

// limiterFor returns (creating if needed) the per-target limiter for host.
func (g *RateLimitGroup) limiterFor(target string) *RateLimiter {
	g.mu.Lock()
	defer g.mu.Unlock()
	l, ok := g.targets[target]
	if !ok {
		l = NewRateLimiter(fmt.Sprintf("target:%s", target), g.perTargetRate, g.minRate, g.adaptive, g.onEvent)
		g.targets[target] = l
	}
	return l
}

// Enabled reports whether any limiter is active.
func (g *RateLimitGroup) Enabled() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.global != nil || g.perTargetRate > 0
}

// Wait blocks until both the global and the per-target limiter grant a
// token. Waiting on both means the stricter of the two limits applies.
func (g *RateLimitGroup) Wait(ctx context.Context, target string) error {
	g.mu.Lock()
	global := g.global
	perTarget := g.perTargetRate > 0
	g.mu.Unlock()

	if global != nil {
		if err := global.Wait(ctx); err != nil {
			return err
		}
	}
	if perTarget {
		if err := g.limiterFor(target).Wait(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Feedback forwards a throttling/success signal to the global limiter and
// the per-target limiter of the affected host.
func (g *RateLimitGroup) Feedback(target string, throttled bool) {
	g.mu.Lock()
	global := g.global
	perTarget := g.perTargetRate > 0
	g.mu.Unlock()
	if global != nil {
		global.Feedback(throttled)
	}
	if perTarget {
		g.limiterFor(target).Feedback(throttled)
	}
}

// SetRates dynamically adjusts the limits at runtime. A value <= 0 disables
// the respective limiter. Existing waiters are woken up and re-reserve.
func (g *RateLimitGroup) SetRates(globalRate, perTargetRate float64, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if globalRate > 0 {
		if g.global == nil {
			g.global = NewRateLimiter("global", globalRate, g.minRate, g.adaptive, g.onEvent)
		} else {
			g.global.SetRate(globalRate, reason)
		}
	} else if g.global != nil {
		g.global = nil
		if g.onEvent != nil {
			g.onEvent(RateAdjustEvent{Time: time.Now(), Scope: "global", NewRate: 0, Reason: reason + " (limiter disabled)"})
		}
	}

	if perTargetRate > 0 {
		changed := perTargetRate != g.perTargetRate
		g.perTargetRate = perTargetRate
		if changed {
			for _, l := range g.targets {
				l.SetRate(perTargetRate, reason)
			}
		}
	} else if g.perTargetRate > 0 {
		g.perTargetRate = 0
		if g.onEvent != nil {
			g.onEvent(RateAdjustEvent{Time: time.Now(), Scope: "per-target", NewRate: 0, Reason: reason + " (limiter disabled)"})
		}
	}
}
