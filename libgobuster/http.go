package libgobuster

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// HTTPHeader holds a single key value pair of a HTTP header
type HTTPHeader struct {
	Name  string
	Value string
}

// HTTPClient represents a http object
type HTTPClient struct {
	client                *http.Client
	userAgent             string
	defaultUserAgent      string
	username              string
	password              string
	headers               []HTTPHeader
	noCanonicalizeHeaders bool
	cookies               string
	method                string
	host                  string
	logger                *Logger
	rateLimiter           *RateLimitGroup
}

// RequestOptions is used to pass options to a single individual request
type RequestOptions struct {
	Host                     string
	Body                     io.Reader
	ReturnBody               bool
	ModifiedHeaders          []HTTPHeader
	UpdatedBasicAuthUsername string
	UpdatedBasicAuthPassword string
}

// NewHTTPClient returns a new HTTPClient
func NewHTTPClient(opt *HTTPOptions, logger *Logger) (*HTTPClient, error) {
	var proxyURLFunc func(*http.Request) (*url.URL, error)
	var client HTTPClient
	proxyURLFunc = http.ProxyFromEnvironment

	if opt == nil {
		return nil, errors.New("options is nil")
	}

	if opt.Proxy != "" {
		proxyURL, err := url.Parse(opt.Proxy)
		if err != nil {
			return nil, fmt.Errorf("proxy URL is invalid (%w)", err)
		}
		proxyURLFunc = http.ProxyURL(proxyURL)
	}

	var redirectFunc func(req *http.Request, via []*http.Request) error
	if !opt.FollowRedirect {
		redirectFunc = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		redirectFunc = nil
	}

	tlsConfig := tls.Config{
		InsecureSkipVerify: opt.NoTLSValidation, // nolint:gosec
		// enable TLS1.0 and TLS1.1 support
		MinVersion: tls.VersionTLS10,
	}
	if opt.TLSCertificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*opt.TLSCertificate}
	}
	if opt.TLSRenegotiation {
		tlsConfig.Renegotiation = tls.RenegotiateOnceAsClient
	}

	transport := &http.Transport{
		Proxy:               proxyURLFunc,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig:     &tlsConfig,
	}

	// set specific network interface
	if opt.LocalAddr != nil {
		logger.Debugf("Setting local address to %s", opt.LocalAddr.String())
		dialer := &net.Dialer{
			Timeout:   opt.Timeout,
			LocalAddr: opt.LocalAddr,
		}
		transport.DialContext = dialer.DialContext
	}

	client.client = &http.Client{
		Timeout:       opt.Timeout,
		CheckRedirect: redirectFunc,
		Transport:     transport,
	}

	client.username = opt.Username
	client.password = opt.Password
	client.userAgent = opt.UserAgent
	client.defaultUserAgent = DefaultUserAgent()
	client.headers = opt.Headers
	client.noCanonicalizeHeaders = opt.NoCanonicalizeHeaders
	client.cookies = opt.Cookies
	client.method = opt.Method
	if client.method == "" {
		client.method = http.MethodGet
	}
	// Host header needs to be set separately
	for _, h := range opt.Headers {
		if h.Name == "Host" {
			client.host = h.Value
			break
		}
	}
	client.logger = logger
	client.rateLimiter = opt.RateLimiter
	return &client, nil
}

const (
	// rateRetryMaxAttempts is the total number of attempts for a request
	// that gets throttled (429/503) or whose connection is reset. Only
	// active when a rate limiter is configured.
	rateRetryMaxAttempts = 4
	rateRetryBaseBackoff = 500 * time.Millisecond
	rateRetryMaxBackoff  = 5 * time.Second
)

// Request makes a http request and returns the status, the content length, the headers, the body and an error
// if you want the body returned set the corresponding property inside RequestOptions
func (client *HTTPClient) Request(ctx context.Context, fullURL url.URL, opts RequestOptions) (int, int64, http.Header, []byte, error) {
	resp, err := client.makeRequestThrottled(ctx, fullURL, opts)
	if err != nil {
		// ignore context canceled errors
		if errors.Is(ctx.Err(), context.Canceled) {
			return 0, 0, nil, nil, nil
		}
		return 0, 0, nil, nil, err
	}
	defer resp.Body.Close()

	var body []byte
	var length int64
	if opts.ReturnBody {
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return 0, 0, nil, nil, fmt.Errorf("could not read body %w", err)
		}
		length = int64(len(body))
	} else {
		// DO NOT REMOVE!
		// absolutely needed so golang will reuse connections!
		length, err = io.Copy(io.Discard, resp.Body)
		if err != nil {
			return 0, 0, nil, nil, err
		}
	}

	return resp.StatusCode, length, resp.Header, body, nil
}

// isThrottledStatus reports whether the status code signals server side
// rate limiting
func isThrottledStatus(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable
}

// isConnectionReset reports whether the error is a connection reset by the peer
func isConnectionReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}

// sleepContext sleeps for d or returns early when the context is canceled
func sleepContext(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// makeRequestThrottled wraps makeRequest with rate limiting, backoff based
// requeuing on throttling responses / connection resets and adaptive
// feedback. Without a configured rate limiter it behaves exactly like
// makeRequest.
func (client *HTTPClient) makeRequestThrottled(ctx context.Context, fullURL url.URL, opts RequestOptions) (*http.Response, error) {
	limiter := client.rateLimiter
	if limiter == nil {
		return client.makeRequest(ctx, fullURL, opts)
	}

	target := fullURL.Host
	backoff := rateRetryBaseBackoff

	for attempt := 1; ; attempt++ {
		if err := limiter.Wait(ctx, target); err != nil {
			// context canceled while waiting for a token
			return nil, err
		}

		resp, err := client.makeRequest(ctx, fullURL, opts)
		if err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil, err
			}
			// a connection reset is requeued with backoff instead of being
			// reported as a miss right away
			if isConnectionReset(err) && attempt < rateRetryMaxAttempts {
				limiter.Feedback(target, true)
				client.logger.Debugf("connection reset by %s, requeuing request after %s", target, backoff)
				sleepContext(ctx, backoff)
				backoff = min(backoff*2, rateRetryMaxBackoff)
				continue
			}
			return nil, err
		}

		if isThrottledStatus(resp.StatusCode) && attempt < rateRetryMaxAttempts {
			limiter.Feedback(target, true)
			wait := backoff
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if seconds, serr := strconv.Atoi(strings.TrimSpace(ra)); serr == nil && seconds > 0 {
					wait = time.Duration(seconds) * time.Second
				}
			}
			// drain and close so the connection can be reused
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			client.logger.Debugf("target %s throttled us (status %d), requeuing request after %s", target, resp.StatusCode, wait)
			sleepContext(ctx, wait)
			backoff = min(backoff*2, rateRetryMaxBackoff)
			continue
		}

		limiter.Feedback(target, false)
		return resp, nil
	}
}

func (client *HTTPClient) makeRequest(ctx context.Context, fullURL url.URL, opts RequestOptions) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, client.method, fullURL.String(), opts.Body)
	if err != nil {
		return nil, err
	}

	if client.cookies != "" {
		req.Header.Set("Cookie", client.cookies)
	}

	// Use host for VHOST mode on a per-request basis, otherwise the one provided from headers
	if opts.Host != "" {
		req.Host = opts.Host
	} else if client.host != "" {
		req.Host = client.host
	}

	if client.userAgent != "" {
		req.Header.Set("User-Agent", client.userAgent)
	} else {
		req.Header.Set("User-Agent", client.defaultUserAgent)
	}

	// add custom headers
	// if ModifiedHeaders are supplied use those, otherwise use the original ones
	// currently only relevant on fuzzing
	if len(opts.ModifiedHeaders) > 0 {
		for _, h := range opts.ModifiedHeaders {
			// empty headers are not valid (happens when fuzzing the host header for example because the slice is initialized with the provided header length)
			if h.Name == "" {
				continue
			}

			if client.noCanonicalizeHeaders {
				// https://stackoverflow.com/questions/26351716/how-to-keep-key-case-sensitive-in-request-header-using-golang
				req.Header[h.Name] = []string{h.Value}
			} else {
				req.Header.Set(h.Name, h.Value)
			}
		}
	} else {
		for _, h := range client.headers {
			if client.noCanonicalizeHeaders {
				// https://stackoverflow.com/questions/26351716/how-to-keep-key-case-sensitive-in-request-header-using-golang
				req.Header[h.Name] = []string{h.Value}
			} else {
				req.Header.Set(h.Name, h.Value)
			}
		}
	}

	if opts.UpdatedBasicAuthUsername != "" {
		req.SetBasicAuth(opts.UpdatedBasicAuthUsername, opts.UpdatedBasicAuthPassword)
	} else if client.username != "" {
		req.SetBasicAuth(client.username, client.password)
	}

	if client.logger.debug {
		dump, err := httputil.DumpRequestOut(req, false)
		if err != nil {
			return nil, err
		}
		client.logger.Debugf("%s", dump)
	}

	resp, err := client.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			if strings.HasPrefix(ue.Err.Error(), "x509") {
				return nil, fmt.Errorf("invalid certificate: %w", ue.Err)
			}
		}
		return nil, err
	}

	return resp, nil
}
