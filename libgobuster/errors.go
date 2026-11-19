package libgobuster

import "errors"

var (
	ErrTimeout           = errors.New("timeout occurred during the request")
	ErrEOF               = errors.New("server closed connection without sending any data back. Maybe you are connecting via https to on http port or vice versa?")
	ErrConnectionRefused = errors.New("connection refused")
	// ErrRateLimited is returned when a target sent a rate limit signal and the
	// request could not be completed after retrying.
	ErrRateLimited = errors.New("target is rate limiting requests")
	// ErrRateLimitExhausted is returned once a target kept rate limiting and
	// enumeration for it has been stopped.
	ErrRateLimitExhausted = errors.New("target kept rate limiting, enumeration stopped for this target")
)
