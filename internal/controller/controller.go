// Package controller holds the HTTP handlers of pm25-auth: it decodes and
// validates requests, calls the service and writes the views.
package controller

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"pm25/auth/internal/platform/httpx"
	"pm25/auth/internal/service"
)

type Controller struct {
	svc     *service.Service
	issuer  *service.TokenIssuer
	keys    *service.KeySet
	ping    func(ctx context.Context) error
	limiter func(http.Handler) http.Handler
}

// New builds the controller. ping checks the database for /health; limiter
// wraps every route except /health and the JWKS (nil: no limit).
func New(svc *service.Service, issuer *service.TokenIssuer, keys *service.KeySet,
	ping func(ctx context.Context) error, limiter func(http.Handler) http.Handler) *Controller {
	if limiter == nil {
		limiter = func(h http.Handler) http.Handler { return h }
	}
	return &Controller{svc: svc, issuer: issuer, keys: keys, ping: ping, limiter: limiter}
}

func (c *Controller) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/health", c.health)
	mux.HandleFunc("GET /.well-known/jwks.json", c.jwks)

	limit := func(h http.HandlerFunc) http.Handler { return c.limiter(h) }
	mux.Handle("POST /api/v1/auth/register", limit(c.register))
	mux.Handle("POST /api/v1/auth/login", limit(c.login))
	mux.Handle("POST /api/v1/auth/refresh", limit(c.refresh))
	mux.Handle("POST /api/v1/auth/logout", limit(c.logout))
	mux.Handle("GET /api/v1/me", limit(c.requireAuth(c.me)))
	mux.Handle("GET /api/v1/admin/users", limit(c.requireAdmin(c.listUsers)))
	mux.Handle("PATCH /api/v1/admin/users/{id}", limit(c.requireAdmin(c.updateUser)))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.Error(w, http.StatusNotFound, "NOT_FOUND", "Unknown route")
	})
}

// ---- identity of the request (from the access token)

type identityKey struct{}

func identity(ctx context.Context) service.Identity {
	id, _ := ctx.Value(identityKey{}).(service.Identity)
	return id
}

// requireAuth answers 401 unless the request carries a valid access token.
func (c *Controller) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		raw = strings.TrimSpace(raw)
		if !strings.EqualFold(scheme, "Bearer") || raw == "" {
			httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing access token")
			return
		}
		id, err := c.issuer.Verify(raw)
		if errors.Is(err, service.ErrTokenExpired) {
			httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Access token expired")
			return
		}
		if err != nil {
			httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid access token")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)))
	}
}

// requireAdmin wraps requireAuth and answers 403 for any other role. The role
// comes from the token, so a change applies at the next refresh.
func (c *Controller) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return c.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if identity(r.Context()).Role != "admin" {
			httpx.Error(w, http.StatusForbidden, "FORBIDDEN", "Admin role required")
			return
		}
		next(w, r)
	})
}

// writeError maps the errors of the service to the error codes of the contract.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	var verr *service.ValidationError
	switch {
	case errors.As(err, &verr):
		httpx.Validation(w, verr.Msg)
	case errors.Is(err, service.ErrInvalidCredentials):
		httpx.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid e-mail or password")
	case errors.Is(err, service.ErrInvalidRefreshToken):
		httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid refresh token")
	case errors.Is(err, service.ErrSelfUpdate):
		httpx.Error(w, http.StatusForbidden, "FORBIDDEN", "An admin cannot change their own role or status")
	case errors.Is(err, service.ErrUserNotFound):
		httpx.Error(w, http.StatusNotFound, "NOT_FOUND", "Unknown user")
	case errors.Is(err, service.ErrEmailTaken):
		httpx.Error(w, http.StatusConflict, "EMAIL_TAKEN", "This e-mail is already registered")
	default:
		httpx.Internal(w, r, err)
	}
}

const healthTimeout = 2 * time.Second
