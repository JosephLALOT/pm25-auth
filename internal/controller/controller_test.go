package controller_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"pm25/auth/internal/controller"
	"pm25/auth/internal/memstore"
	"pm25/auth/internal/platform/middleware"
	"pm25/auth/internal/service"
)

const (
	issuer   = "http://localhost:8001"
	audience = "pm25-api"
	password = "correct-horse-battery"
)

type app struct {
	t      *testing.T
	h      http.Handler
	svc    *service.Service
	store  *memstore.Store
	dbDown bool
}

func newApp(t *testing.T, limiter func(http.Handler) http.Handler) *app {
	t.Helper()
	keys, err := service.EphemeralKeySet()
	if err != nil {
		t.Fatal(err)
	}
	ti := service.NewTokenIssuer(keys, issuer, audience, 15*time.Minute)
	store := memstore.New()
	cheap := service.Hasher{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}
	a := &app{t: t, store: store, svc: service.New(store.Users(), store.Tokens(), ti, cheap, 7*24*time.Hour)}

	ping := func(context.Context) error {
		if a.dbDown {
			return errors.New("connection refused")
		}
		return nil
	}
	mux := http.NewServeMux()
	controller.New(a.svc, ti, keys, ping, limiter).Routes(mux)
	a.h = middleware.Chain(mux, middleware.RequestLog, middleware.Recover)
	return a
}

type response struct {
	*httptest.ResponseRecorder
	t *testing.T
}

// json decodes the body into a map.
func (r response) json() map[string]any {
	r.t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(r.Body.Bytes(), &m); err != nil {
		r.t.Fatalf("body %q: %v", r.Body, err)
	}
	return m
}

func (r response) errorCode() string {
	r.t.Helper()
	e, _ := r.json()["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

func (a *app) do(method, path, body, token string) response {
	a.t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	a.h.ServeHTTP(w, req)
	return response{ResponseRecorder: w, t: a.t}
}

func (a *app) expect(r response, status int, code string) {
	a.t.Helper()
	if r.Code != status {
		a.t.Fatalf("status %d, want %d: %s", r.Code, status, r.Body)
	}
	if code != "" && r.errorCode() != code {
		a.t.Fatalf("error code %q, want %q: %s", r.errorCode(), code, r.Body)
	}
}

func (a *app) register(email string) map[string]any {
	a.t.Helper()
	r := a.do("POST", "/api/v1/auth/register", `{"email":"`+email+`","password":"`+password+`","display_name":"Test"}`, "")
	a.expect(r, http.StatusCreated, "")
	return r.json()
}

func (a *app) login(email string) (access, refresh string) {
	a.t.Helper()
	r := a.do("POST", "/api/v1/auth/login", `{"email":"`+email+`","password":"`+password+`"}`, "")
	a.expect(r, http.StatusOK, "")
	m := r.json()
	return m["access_token"].(string), m["refresh_token"].(string)
}

func (a *app) admin() (id, access string) {
	a.t.Helper()
	u, err := a.svc.CreateAdmin(context.Background(), "admin@example.com", password, "Admin")
	if err != nil {
		a.t.Fatal(err)
	}
	access, _ = a.login("admin@example.com")
	return u.ID, access
}

func TestRegisterLoginMe(t *testing.T) {
	a := newApp(t, nil)
	u := a.register("An.Nguyen@Example.com")
	for _, k := range []string{"id", "email", "display_name", "role", "is_active", "created_at"} {
		if _, ok := u[k]; !ok {
			t.Errorf("register: missing %s in %v", k, u)
		}
	}
	if _, ok := u["last_login_at"]; ok {
		t.Error("register: last_login_at must be omitted, not null")
	}
	if u["email"] != "an.nguyen@example.com" || u["role"] != "user" || len(u) != 6 {
		t.Errorf("register: %v", u)
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", u["created_at"].(string)); err != nil {
		t.Errorf("created_at %q is not UTC without fractions", u["created_at"])
	}

	r := a.do("POST", "/api/v1/auth/login", `{"email":"an.nguyen@example.com","password":"`+password+`"}`, "")
	a.expect(r, http.StatusOK, "")
	if r.Header().Get("Cache-Control") != "no-store" {
		t.Error("token response may be cached")
	}
	pair := r.json()
	if pair["expires_in"] != float64(900) || len(pair) != 3 {
		t.Errorf("token pair %v", pair)
	}

	me := a.do("GET", "/api/v1/me", "", pair["access_token"].(string))
	a.expect(me, http.StatusOK, "")
	if m := me.json(); m["id"] != u["id"] || m["last_login_at"] == nil {
		t.Errorf("me: %v", m)
	}
}

func TestRegisterErrors(t *testing.T) {
	a := newApp(t, nil)
	a.register("an@example.com")

	a.expect(a.do("POST", "/api/v1/auth/register", `{"email":"AN@example.com","password":"`+password+`","display_name":"X"}`, ""),
		http.StatusConflict, "EMAIL_TAKEN")
	a.expect(a.do("POST", "/api/v1/auth/register", `{"email":"b@example.com","password":"short","display_name":"X"}`, ""),
		http.StatusBadRequest, "VALIDATION_ERROR")
	a.expect(a.do("POST", "/api/v1/auth/register", `{"email":5}`, ""), http.StatusBadRequest, "VALIDATION_ERROR")
	a.expect(a.do("POST", "/api/v1/auth/register", `{"email":`, ""), http.StatusBadRequest, "VALIDATION_ERROR")
	a.expect(a.do("POST", "/api/v1/auth/register", `{} {}`, ""), http.StatusBadRequest, "VALIDATION_ERROR")
	a.expect(a.do("POST", "/api/v1/auth/register", "", ""), http.StatusBadRequest, "VALIDATION_ERROR")
	big := `{"display_name":"` + strings.Repeat("x", 20<<10) + `"}`
	a.expect(a.do("POST", "/api/v1/auth/register", big, ""), http.StatusBadRequest, "VALIDATION_ERROR")
}

func TestLoginErrors(t *testing.T) {
	a := newApp(t, nil)
	a.register("an@example.com")

	r := a.do("POST", "/api/v1/auth/login", `{"email":"an@example.com","password":"wrong-password"}`, "")
	a.expect(r, http.StatusUnauthorized, "INVALID_CREDENTIALS")
	unknown := a.do("POST", "/api/v1/auth/login", `{"email":"x@example.com","password":"wrong-password"}`, "")
	if unknown.Body.String() != r.Body.String() {
		t.Errorf("unknown e-mail and wrong password differ: %s vs %s", unknown.Body, r.Body)
	}
	a.expect(a.do("POST", "/api/v1/auth/login", `{"email":"an@example.com"}`, ""), http.StatusBadRequest, "VALIDATION_ERROR")
}

func TestRefreshAndLogout(t *testing.T) {
	a := newApp(t, nil)
	a.register("an@example.com")
	_, refresh := a.login("an@example.com")

	r := a.do("POST", "/api/v1/auth/refresh", `{"refresh_token":"`+refresh+`"}`, "")
	a.expect(r, http.StatusOK, "")
	next := r.json()["refresh_token"].(string)

	a.expect(a.do("POST", "/api/v1/auth/refresh", `{"refresh_token":"`+refresh+`"}`, ""), http.StatusUnauthorized, "UNAUTHORIZED")
	a.expect(a.do("POST", "/api/v1/auth/logout", `{"refresh_token":"`+next+`"}`, ""), http.StatusNoContent, "")
	a.expect(a.do("POST", "/api/v1/auth/refresh", `{"refresh_token":"`+next+`"}`, ""), http.StatusUnauthorized, "UNAUTHORIZED")
	a.expect(a.do("POST", "/api/v1/auth/logout", `{"refresh_token":"unknown"}`, ""), http.StatusNoContent, "")
	a.expect(a.do("POST", "/api/v1/auth/logout", `{}`, ""), http.StatusBadRequest, "VALIDATION_ERROR")
}

func TestMeNeedsAValidToken(t *testing.T) {
	a := newApp(t, nil)
	r := a.do("GET", "/api/v1/me", "", "")
	a.expect(r, http.StatusUnauthorized, "UNAUTHORIZED")
	a.expect(a.do("GET", "/api/v1/me", "", "garbage"), http.StatusUnauthorized, "UNAUTHORIZED")

	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
	w := httptest.NewRecorder()
	a.h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Basic auth: %d", w.Code)
	}
}

func TestAdminListUsers(t *testing.T) {
	a := newApp(t, nil)
	a.register("an@example.com")
	b := a.register("binh@example.com")
	userToken, _ := a.login("an@example.com")
	_, adminToken := a.admin()

	a.expect(a.do("GET", "/api/v1/admin/users", "", userToken), http.StatusForbidden, "FORBIDDEN")
	a.expect(a.do("GET", "/api/v1/admin/users", "", ""), http.StatusUnauthorized, "UNAUTHORIZED")

	r := a.do("GET", "/api/v1/admin/users?page=1&page_size=2", "", adminToken)
	a.expect(r, http.StatusOK, "")
	page := r.json()
	items := page["items"].([]any)
	if page["total"] != float64(3) || page["page_size"] != float64(2) || len(items) != 2 ||
		items[0].(map[string]any)["email"] != "admin@example.com" {
		t.Fatalf("page %v", page)
	}

	r = a.do("GET", "/api/v1/admin/users?ids="+strings.ToUpper(b["id"].(string)), "", adminToken)
	a.expect(r, http.StatusOK, "")
	if m := r.json(); m["total"] != float64(1) || m["items"].([]any)[0].(map[string]any)["id"] != b["id"] {
		t.Fatalf("ids filter: %v", m)
	}

	for _, q := range []string{"ids=", "ids=nope", "page_size=101", "page=0", "ids=" + strings.Repeat(b["id"].(string)+",", 101)} {
		a.expect(a.do("GET", "/api/v1/admin/users?"+q, "", adminToken), http.StatusBadRequest, "VALIDATION_ERROR")
	}
}

func TestAdminUpdateUser(t *testing.T) {
	a := newApp(t, nil)
	u := a.register("an@example.com")
	adminID, adminToken := a.admin()
	path := "/api/v1/admin/users/" + u["id"].(string)

	r := a.do("PATCH", path, `{"role":"admin"}`, adminToken)
	a.expect(r, http.StatusOK, "")
	if m := r.json(); m["role"] != "admin" || m["is_active"] != true {
		t.Fatalf("updated %v", m)
	}
	if len(a.store.Events) != 1 || a.store.Events[0].UserID != adminID {
		t.Fatalf("audit %+v", a.store.Events)
	}

	a.expect(a.do("PATCH", "/api/v1/admin/users/"+adminID, `{"is_active":false}`, adminToken), http.StatusForbidden, "FORBIDDEN")
	a.expect(a.do("PATCH", "/api/v1/admin/users/00000000-0000-4000-8000-000000000000", `{"role":"user"}`, adminToken),
		http.StatusNotFound, "NOT_FOUND")
	a.expect(a.do("PATCH", "/api/v1/admin/users/42", `{"role":"user"}`, adminToken), http.StatusBadRequest, "VALIDATION_ERROR")
	a.expect(a.do("PATCH", path, `{}`, adminToken), http.StatusBadRequest, "VALIDATION_ERROR")
	a.expect(a.do("PATCH", path, `{"role":"root"}`, adminToken), http.StatusBadRequest, "VALIDATION_ERROR")
	a.expect(a.do("PATCH", path, `{"is_active":"no"}`, adminToken), http.StatusBadRequest, "VALIDATION_ERROR")
}

// The API verifies tokens with the JWKS only (platform/authn of pm25-platform):
// do the same here, so both sides agree on the format.
func TestJWKSVerifiesIssuedTokens(t *testing.T) {
	a := newApp(t, nil)
	a.register("an@example.com")
	access, _ := a.login("an@example.com")

	r := a.do("GET", "/.well-known/jwks.json", "", "")
	a.expect(r, http.StatusOK, "")
	if r.Header().Get("Cache-Control") != "public, max-age=300" {
		t.Errorf("Cache-Control %q", r.Header().Get("Cache-Control"))
	}
	var set struct {
		Keys []struct{ Kty, Crv, X, Kid, Use, Alg string }
	}
	if err := json.Unmarshal(r.Body.Bytes(), &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("jwks %s: %v", r.Body, err)
	}
	k := set.Keys[0]
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Use != "sig" || k.Alg != "EdDSA" || err != nil || len(x) != ed25519.PublicKeySize {
		t.Fatalf("jwk %+v", k)
	}

	c := &jwt.RegisteredClaims{}
	_, err = jwt.ParseWithClaims(access, c,
		func(tok *jwt.Token) (any, error) {
			if tok.Header["kid"] != k.Kid {
				return nil, errors.New("unknown kid")
			}
			return ed25519.PublicKey(x), nil
		},
		jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatalf("the API would reject the token: %v", err)
	}
}

func TestHealth(t *testing.T) {
	a := newApp(t, nil)
	r := a.do("GET", "/api/v1/health", "", "")
	a.expect(r, http.StatusOK, "")
	m := r.json()
	if m["status"] != "ok" || m["database"].(map[string]any)["reachable"] != true || !strings.HasPrefix(m["kid"].(string), "dev-") {
		t.Fatalf("health %v", m)
	}

	a.dbDown = true
	r = a.do("GET", "/api/v1/health", "", "")
	a.expect(r, http.StatusServiceUnavailable, "")
	if m := r.json(); m["status"] != "down" || m["database"].(map[string]any)["reachable"] != false {
		t.Fatalf("health %v", m)
	}
}

func TestUnknownRoute(t *testing.T) {
	a := newApp(t, nil)
	a.expect(a.do("GET", "/api/v1/nothing", "", ""), http.StatusNotFound, "NOT_FOUND")
}

func TestRateLimitSparesHealthAndJWKS(t *testing.T) {
	a := newApp(t, middleware.NewRateLimiter(0.001, 1, false).Wrap)
	body := `{"email":"x@example.com","password":"whatever-password"}`
	a.expect(a.do("POST", "/api/v1/auth/login", body, ""), http.StatusUnauthorized, "INVALID_CREDENTIALS")
	a.expect(a.do("POST", "/api/v1/auth/login", body, ""), http.StatusTooManyRequests, "RATE_LIMITED")
	a.expect(a.do("GET", "/api/v1/me", "", ""), http.StatusTooManyRequests, "RATE_LIMITED")
	for range 3 {
		a.expect(a.do("GET", "/api/v1/health", "", ""), http.StatusOK, "")
		a.expect(a.do("GET", "/.well-known/jwks.json", "", ""), http.StatusOK, "")
	}
}
