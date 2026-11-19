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
	"strings"
	"sync"
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
}

// RedirectHop is a single entry of a recorded redirect chain.
type RedirectHop struct {
	// Status is the status code that issued the redirect.
	Status int
	// Location is the target the redirect pointed to (as sent by the server).
	Location string
	// URL is the fully resolved URL the next request was sent to.
	URL string
}

// RedirectRecorder collects the redirect chain of a single request.
// A fresh instance must be supplied per request via RequestOptions.
type RedirectRecorder struct {
	mu     sync.Mutex
	hops   []RedirectHop
	loop   bool
	cutOff bool
}

// record is invoked by the http client CheckRedirect hook.
func (r *RedirectRecorder) record(hop RedirectHop, loop, cutOff bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hops = append(r.hops, hop)
	if loop {
		r.loop = true
	}
	if cutOff {
		r.cutOff = true
	}
}

// Hops returns a copy of the recorded redirect chain.
func (r *RedirectRecorder) Hops() []RedirectHop {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RedirectHop, len(r.hops))
	copy(out, r.hops)
	return out
}

// Loop reports whether the redirect chain contained a cycle.
func (r *RedirectRecorder) Loop() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.loop
}

// CutOff reports whether the chain was truncated at MaxRedirectHops.
func (r *RedirectRecorder) CutOff() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cutOff
}

// RequestOptions is used to pass options to a single individual request
type RequestOptions struct {
	Host                     string
	Body                     io.Reader
	ReturnBody               bool
	ModifiedHeaders          []HTTPHeader
	UpdatedBasicAuthUsername string
	UpdatedBasicAuthPassword string
	// RedirectRecorder, when set, records every redirect hop of this request.
	// It must not be reused concurrently across requests.
	RedirectRecorder *RedirectRecorder
}

type redirectRecorderContextKey struct{}

func withRedirectRecorder(ctx context.Context, r *RedirectRecorder) context.Context {
	if r == nil {
		return ctx
	}
	return context.WithValue(ctx, redirectRecorderContextKey{}, r)
}

func redirectRecorderFromContext(ctx context.Context) *RedirectRecorder {
	r, _ := ctx.Value(redirectRecorderContextKey{}).(*RedirectRecorder)
	return r
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
		// Default behaviour is preserved (up to 10 automatic hops). When a
		// request carries a RedirectRecorder the chain - including cycles and
		// truncation - is recorded while the response handling is unchanged.
		redirectFunc = func(req *http.Request, via []*http.Request) error {
			recorder := redirectRecorderFromContext(req.Context())
			if recorder == nil {
				return checkRedirectLimit(len(via))
			}

			// req.Response is the response that issued this redirect
			// (the previous hop); requests inside via only carry URLs
			hop := RedirectHop{URL: req.URL.String()}
			if req.Response != nil {
				hop.Status = req.Response.StatusCode
				hop.Location = req.Response.Header.Get("Location")
			}

			visited := make(map[string]bool, len(via)+1)
			for _, v := range via {
				visited[v.URL.String()] = true
			}
			loop := visited[req.URL.String()]
			cutOff := len(via) >= MaxRedirectHops
			recorder.record(hop, loop, cutOff)

			switch {
			case loop || cutOff:
				// stop following but keep the last response; the recorded
				// flags surface the anomalous chain instead of an error loop
				return http.ErrUseLastResponse
			default:
				return checkRedirectLimit(len(via))
			}
		}
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
	return &client, nil
}

// Request makes a http request and returns the status, the content length, the headers, the body and an error
// if you want the body returned set the corresponding property inside RequestOptions
func (client *HTTPClient) Request(ctx context.Context, fullURL url.URL, opts RequestOptions) (int, int64, http.Header, []byte, error) {
	resp, err := client.makeRequest(ctx, fullURL, opts)
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

func checkRedirectLimit(viaLen int) error {
	// mirrors net/http.defaultCheckRedirect with the exported limit constant
	if viaLen >= MaxRedirectHops {
		return fmt.Errorf("stopped after %d redirects", MaxRedirectHops)
	}
	return nil
}

func (client *HTTPClient) makeRequest(ctx context.Context, fullURL url.URL, opts RequestOptions) (*http.Response, error) {
	ctx = withRedirectRecorder(ctx, opts.RedirectRecorder)
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
