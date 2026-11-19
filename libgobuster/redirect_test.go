package libgobuster

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func newRedirectClient(t *testing.T, follow bool) *HTTPClient {
	t.Helper()
	log := NewLogger(false)
	c, err := NewHTTPClient(&HTTPOptions{FollowRedirect: follow}, log)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return c
}

func TestRedirectRecorderChain(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/middle", http.StatusFound)
	})
	mux.HandleFunc("/middle", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/end", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("done"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := newRedirectClient(t, true)
	u, _ := url.Parse(ts.URL + "/start")
	rec := &RedirectRecorder{}

	status, _, _, _, err := client.Request(t.Context(), *u, RequestOptions{RedirectRecorder: rec})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected final 200, got %d", status)
	}
	hops := rec.Hops()
	if len(hops) != 2 {
		t.Fatalf("expected 2 hops, got %d: %+v", len(hops), hops)
	}
	if hops[0].Status != http.StatusFound || hops[1].Status != http.StatusMovedPermanently {
		t.Fatalf("hop status codes wrong: %+v", hops)
	}
	if rec.Loop() || rec.CutOff() {
		t.Fatal("normal chain must not be flagged as loop or truncated")
	}
}

func TestRedirectRecorderLoop(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/a", http.StatusFound)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := newRedirectClient(t, true)
	u, _ := url.Parse(ts.URL + "/a")
	rec := &RedirectRecorder{}

	// must terminate on its own instead of looping forever
	status, _, _, _, err := client.Request(t.Context(), *u, RequestOptions{RedirectRecorder: rec})
	if err != nil {
		t.Fatalf("a redirect loop must be handled, not error out: %v", err)
	}
	if status != http.StatusFound {
		t.Fatalf("expected the last 302 response, got %d", status)
	}
	if !rec.Loop() {
		t.Fatalf("cycle not detected: %+v", rec.Hops())
	}
}

func TestRedirectRecorderCutOff(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/r", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/r", http.StatusFound)
	})
	// self redirect hits the same URL immediately, so build a longer distinct
	// chain instead
	for i := range MaxRedirectHops + 2 {
		from := "/h" + strconv.Itoa(i)
		to := "/h" + strconv.Itoa(i+1)
		mux.HandleFunc(from, func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, to, http.StatusFound)
		})
	}
	mux.HandleFunc("/h"+strconv.Itoa(MaxRedirectHops+2), func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("end"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := newRedirectClient(t, true)
	u, _ := url.Parse(ts.URL + "/h0")
	rec := &RedirectRecorder{}

	if _, _, _, _, err := client.Request(t.Context(), *u, RequestOptions{RedirectRecorder: rec}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if !rec.CutOff() {
		t.Fatalf("chain longer than %d hops must be marked truncated: %+v", MaxRedirectHops, rec.Hops())
	}
	if len(rec.Hops()) > MaxRedirectHops {
		t.Fatalf("recorded chain must not exceed the hop limit, got %d", len(rec.Hops()))
	}
}

func TestNoRecorderKeepsLegacyRedirectBehaviour(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/end", http.StatusFound)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("done"))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// follow redirects without a recorder behaves exactly like the default
	client := newRedirectClient(t, true)
	u, _ := url.Parse(ts.URL + "/start")
	status, _, _, _, err := client.Request(t.Context(), *u, RequestOptions{})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("default redirect following broken, got %d", status)
	}

	// a client configured not to follow still stops at the first response
	noFollow := newRedirectClient(t, false)
	status, _, _, _, err = noFollow.Request(t.Context(), *u, RequestOptions{})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if status != http.StatusFound {
		t.Fatalf("ErrUseLastResponse behaviour broken, got %d", status)
	}
}
