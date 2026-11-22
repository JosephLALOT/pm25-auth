package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var ok = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

func TestRateLimiterPerIP(t *testing.T) {
	l := NewRateLimiter(1, 3, false)
	now := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }
	h := l.Wrap(ok)

	call := func(ip string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		r.RemoteAddr = ip + ":40000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for i := range 3 {
		if w := call("10.0.0.1"); w.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	w := call("10.0.0.1")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "1" ||
		!strings.Contains(w.Body.String(), `"code":"RATE_LIMITED"`) {
		t.Fatalf("4th request: %d %s", w.Code, w.Body)
	}
	if w := call("10.0.0.2"); w.Code != http.StatusOK {
		t.Fatalf("other IP: %d", w.Code)
	}
	now = now.Add(time.Second)
	if w := call("10.0.0.1"); w.Code != http.StatusOK {
		t.Fatalf("after 1 s: %d", w.Code)
	}

	now = now.Add(10 * time.Minute)
	call("10.0.0.3") // sweeps the idle clients
	if len(l.clients) != 1 {
		t.Fatalf("%d clients kept, want 1", len(l.clients))
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.10:5555"
	r.Header.Add("X-Forwarded-For", "203.0.113.7, 198.51.100.4")
	if ip := ClientIP(r, false); ip != "192.0.2.10" {
		t.Errorf("without proxy: %s", ip)
	}
	if ip := ClientIP(r, true); ip != "198.51.100.4" {
		t.Errorf("behind proxy: %s", ip)
	}
	r.Header.Del("X-Forwarded-For")
	if ip := ClientIP(r, true); ip != "192.0.2.10" {
		t.Errorf("proxy without header: %s", ip)
	}
}

func TestCORS(t *testing.T) {
	h := CORS([]string{"http://localhost:4200"})(ok)

	r := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/login", nil)
	r.Header.Set("Origin", "http://localhost:4200")
	r.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "http://localhost:4200" ||
		!strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight: %d %v", w.Code, w.Header())
	}

	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("unknown origin allowed")
	}
}

func TestRequestID(t *testing.T) {
	h := RequestLog(ok)
	for in, keep := range map[string]bool{"abc-123": true, "": false, "bad id\n": false, strings.Repeat("a", 65): false} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if in != "" {
			r.Header.Set("X-Request-Id", in)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		got := w.Header().Get("X-Request-Id")
		if keep && got != in || !keep && (got == in || len(got) != 16) {
			t.Errorf("X-Request-Id %q -> %q", in, got)
		}
	}
}

func TestRecover(t *testing.T) {
	h := Recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), `"code":"INTERNAL"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
