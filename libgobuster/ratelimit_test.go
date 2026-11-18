package libgobuster

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRateLimiterPacing(t *testing.T) {
	t.Parallel()
	l := NewRateLimiter("global", 100, 1, false, nil)
	ctx := context.Background()

	start := time.Now()
	for range 10 {
		if err := l.Wait(ctx); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}
	elapsed := time.Since(start)
	// 10 tokens at 100 rps => ~90ms after the first free token
	if elapsed < 80*time.Millisecond {
		t.Fatalf("expected pacing of at least 80ms, got %s", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("pacing too slow, got %s", elapsed)
	}
}

func TestRateLimiterDynamicChangeWakesWaiters(t *testing.T) {
	t.Parallel()
	// very slow rate, waiters would block for seconds
	l := NewRateLimiter("global", 1, 0.1, false, nil)
	ctx := context.Background()

	// consume the initial free token
	if err := l.Wait(ctx); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Wait(ctx)
		}()
	}

	// give waiters time to park on their timers, then speed up
	time.Sleep(100 * time.Millisecond)
	l.SetRate(1000, "test speedup")

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("waiters were not woken up after the rate increase")
	}
}

func TestRateLimiterContextCancel(t *testing.T) {
	t.Parallel()
	l := NewRateLimiter("global", 0.1, 0.01, false, nil)
	ctx, cancel := context.WithCancel(context.Background())
	if err := l.Wait(ctx); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
	cancel()
	if err := l.Wait(ctx); err == nil {
		t.Fatal("expected context error from Wait")
	}
}

func TestRateLimiterAdaptive(t *testing.T) {
	t.Parallel()
	var events []RateAdjustEvent
	var mu sync.Mutex
	l := NewRateLimiter("global", 100, 1, true, func(e RateAdjustEvent) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})

	l.Feedback(true)
	if got := l.CurrentRate(); got != 50 {
		t.Fatalf("expected rate 50 after throttle, got %.2f", got)
	}
	l.Feedback(true)
	if got := l.CurrentRate(); got != 25 {
		t.Fatalf("expected rate 25 after second throttle, got %.2f", got)
	}

	// successes below the threshold must not increase the rate
	for range adaptiveSuccessThreshold - 1 {
		l.Feedback(false)
	}
	if got := l.CurrentRate(); got != 25 {
		t.Fatalf("rate increased too early: %.2f", got)
	}

	// not enough time since the decrease passed, still no increase
	l.Feedback(false)
	if got := l.CurrentRate(); got != 25 {
		t.Fatalf("rate increased during recover delay: %.2f", got)
	}

	// fake an old decrease so recovery is allowed
	l.mu.Lock()
	l.lastDecrease = time.Now().Add(-time.Hour)
	l.mu.Unlock()
	for range adaptiveSuccessThreshold {
		l.Feedback(false)
	}
	if got := l.CurrentRate(); got <= 25 {
		t.Fatalf("expected rate recovery, got %.2f", got)
	}

	// rate never exceeds the configured maximum
	for range 10000 {
		l.Feedback(false)
	}
	if got := l.CurrentRate(); got > 100 {
		t.Fatalf("rate exceeded maximum: %.2f", got)
	}

	mu.Lock()
	if len(events) == 0 {
		t.Fatal("expected adjustment events to be emitted")
	}
	for _, e := range events {
		if e.Reason == "" {
			t.Fatal("event without reason")
		}
	}
	mu.Unlock()
}

func TestRateLimiterAdaptiveFloor(t *testing.T) {
	t.Parallel()
	l := NewRateLimiter("global", 100, 5, true, nil)
	for range 20 {
		l.Feedback(true)
	}
	if got := l.CurrentRate(); got != 5 {
		t.Fatalf("expected rate to bottom out at min 5, got %.2f", got)
	}
}

func TestRateLimitGroupStricterWins(t *testing.T) {
	t.Parallel()
	// global allows 1000 rps, per-target only 50 rps => per-target wins
	g, err := NewRateLimitGroup(1000, 50, 1, false)
	if err != nil {
		t.Fatalf("NewRateLimitGroup failed: %v", err)
	}
	ctx := context.Background()
	start := time.Now()
	for range 5 {
		if err := g.Wait(ctx, "example.com"); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}
	elapsed := time.Since(start)
	// 5 tokens at 50 rps => ~80ms
	if elapsed < 70*time.Millisecond {
		t.Fatalf("per-target limit not enforced, 5 requests took only %s", elapsed)
	}

	// and the other way around: global 20 rps, per-target 1000 rps
	g2, err := NewRateLimitGroup(20, 1000, 1, false)
	if err != nil {
		t.Fatalf("NewRateLimitGroup failed: %v", err)
	}
	start = time.Now()
	for range 3 {
		if err := g2.Wait(ctx, "example.com"); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}
	elapsed = time.Since(start)
	// 3 tokens at 20 rps => ~100ms
	if elapsed < 90*time.Millisecond {
		t.Fatalf("global limit not enforced, 3 requests took only %s", elapsed)
	}
}

func TestRateLimitGroupSetRates(t *testing.T) {
	t.Parallel()
	g, err := NewRateLimitGroup(10, 10, 1, false)
	if err != nil {
		t.Fatalf("NewRateLimitGroup failed: %v", err)
	}
	g.SetRates(500, 0, "test")
	if g.global == nil {
		t.Fatal("global limiter missing")
	}
	if got := g.global.CurrentRate(); got != 500 {
		t.Fatalf("expected global rate 500, got %.2f", got)
	}
	if g.perTargetRate != 0 {
		t.Fatalf("expected per-target limiter to be disabled, got %.2f", g.perTargetRate)
	}

	// disabling the global limiter must not block Wait
	g.SetRates(0, 0, "test")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := g.Wait(ctx, "example.com"); err != nil {
		t.Fatalf("Wait blocked after disabling limiters: %v", err)
	}
}

func TestNewRateLimitGroupValidation(t *testing.T) {
	t.Parallel()
	if g, err := NewRateLimitGroup(0, 0, 1, false); g != nil || err != nil {
		t.Fatal("expected nil limiter without error when all limits are disabled")
	}
	if _, err := NewRateLimitGroup(0, 0, 1, true); err == nil {
		t.Fatal("expected error for adaptive without any limit")
	}
	if _, err := NewRateLimitGroup(1, 0, 10, false); err == nil {
		t.Fatal("expected error when rate-limit < rate-min")
	}
}
