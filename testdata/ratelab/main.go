// Command ratelab is a local test server used to validate gobuster's
// structured output and rate limiting features. It serves a few known
// paths, can simulate throttling (429 + Retry-After) and connection resets
// after a configurable number of requests, and logs every request with a
// timestamp so actual request rates can be measured.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

var knownPaths = map[string]string{
	"/admin":  "admin panel",
	"/login":  "login page",
	"/backup": "backup archive",
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "listen address")
	throttleAfter := flag.Int("throttle-after", 0, "start returning 429 after N requests (0 = never)")
	throttleWindow := flag.Duration("throttle-window", 5*time.Second, "how long throttling lasts once triggered")
	resetAfter := flag.Int("reset-after", 0, "reset the TCP connection after N requests (0 = never)")
	resetCount := flag.Int("reset-count", 0, "number of requests to reset once triggered (0 = unlimited)")
	logFile := flag.String("log", "", "file to append request timestamps to")
	flag.Parse()

	var mu sync.Mutex
	var count int
	var throttleUntil time.Time

	var lf *os.File
	if *logFile != "" {
		var err error
		lf, err = os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatal(err)
		}
		defer lf.Close()
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		n := count
		if *throttleAfter > 0 && n == *throttleAfter {
			throttleUntil = time.Now().Add(*throttleWindow)
		}
		throttled := *throttleAfter > 0 && n >= *throttleAfter && time.Now().Before(throttleUntil)
		reset := *resetAfter > 0 && n >= *resetAfter && (*resetCount == 0 || n < *resetAfter+*resetCount)
		mu.Unlock()

		status := 200
		switch {
		case reset:
			// simulate a connection reset by the peer
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, err := hj.Hijack()
				if err == nil {
					if tcp, ok := conn.(*net.TCPConn); ok {
						_ = tcp.SetLinger(0)
					}
					_ = conn.Close()
				}
			}
			status = 0
		case throttled:
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprintln(w, "slow down")
			status = 429
		case r.URL.Path == "/old":
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusMovedPermanently)
			status = 301
		default:
			if body, ok := knownPaths[r.URL.Path]; ok {
				_, _ = fmt.Fprintf(w, "%s\n", body)
				status = 200
			} else {
				w.WriteHeader(http.StatusNotFound)
				status = 404
			}
		}

		if lf != nil {
			mu.Lock()
			_, _ = fmt.Fprintf(lf, "%s %s %d\n", time.Now().Format("15:04:05.000"), r.URL.Path, status)
			mu.Unlock()
		}
	})

	log.Printf("ratelab listening on %s (throttle-after=%d window=%s reset-after=%d)", *addr, *throttleAfter, *throttleWindow, *resetAfter)
	server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
