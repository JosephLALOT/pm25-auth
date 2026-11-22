// Package middleware holds the HTTP middleware of pm25-auth: request id,
// access log, panic recovery, CORS and the per-IP rate limit.
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"pm25/auth/internal/platform/httpx"
)

// Chain applies the middleware so that the first one is the outermost.
func Chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// RequestLog sets X-Request-Id (kept from the request when it looks sane)
// and logs one line per request. Bodies and tokens are never logged.
func RequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !validRequestID(id) {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-Id", id)
		r = r.WithContext(httpx.WithRequestID(r.Context(), id))

		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		slog.Info("request", "request_id", id, "method", r.Method, "path", r.URL.Path,
			"status", sw.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c == '-' || c == '_' || c == '.' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
			return false
		}
	}
	return true
}

func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				slog.Error("panic", "request_id", httpx.RequestID(r.Context()), "path", r.URL.Path, "value", v)
				httpx.Error(w, http.StatusInternalServerError, "INTERNAL", "Internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// CORS allows the listed origins and answers preflight requests.
func CORS(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && slices.Contains(origins, origin) {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
				h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Expose-Headers", "X-Request-Id")
				h.Set("Access-Control-Max-Age", "600")
			}
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimiter is a token bucket per client IP, kept in memory: enough for a
// single instance of the service. Idle buckets are dropped after a few minutes.
type RateLimiter struct {
	rps        rate.Limit
	burst      int
	trustProxy bool
	now        func() time.Time

	mu        sync.Mutex
	clients   map[string]*client
	lastSweep time.Time
}

type client struct {
	lim  *rate.Limiter
	seen time.Time
}

const idleClient = 3 * time.Minute

func NewRateLimiter(rps float64, burst int, trustProxy bool) *RateLimiter {
	return &RateLimiter{
		rps:        rate.Limit(rps),
		burst:      burst,
		trustProxy: trustProxy,
		now:        time.Now,
		clients:    map[string]*client{},
	}
}

// Wrap answers 429 RATE_LIMITED once the client IP has used its budget.
func (l *RateLimiter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(ClientIP(r, l.trustProxy)) {
			w.Header().Set("Retry-After", "1")
			httpx.Error(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *RateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if now.Sub(l.lastSweep) > time.Minute {
		for k, c := range l.clients {
			if now.Sub(c.seen) > idleClient {
				delete(l.clients, k)
			}
		}
		l.lastSweep = now
	}
	c, ok := l.clients[ip]
	if !ok {
		c = &client{lim: rate.NewLimiter(l.rps, l.burst)}
		l.clients[ip] = c
	}
	c.seen = now
	return c.lim.AllowN(now, 1)
}

// ClientIP is the TCP peer address, or with trustProxy the last address of
// X-Forwarded-For (the one added by the proxy in front of the service).
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
