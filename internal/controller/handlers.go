package controller

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"pm25/auth/internal/model"
	"pm25/auth/internal/platform/httpx"
	"pm25/auth/internal/service"
	"pm25/auth/internal/view"
)

// GET /api/v1/health: 200 when the database answers, 503 otherwise.
func (c *Controller) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
	defer cancel()

	var v view.Health
	v.KID = c.keys.KID()
	v.Database.Reachable = c.ping(ctx) == nil
	status := http.StatusOK
	v.Status = "ok"
	if !v.Database.Reachable {
		status, v.Status = http.StatusServiceUnavailable, "down"
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, status, v)
}

// GET /.well-known/jwks.json
func (c *Controller) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	httpx.JSON(w, http.StatusOK, view.NewJWKS(c.keys.Public()))
}

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

// POST /api/v1/auth/register
func (c *Controller) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !httpx.Decode(w, r, &req) {
		return
	}
	u, err := c.svc.Register(r.Context(), req.Email, req.Password, req.DisplayName)
	if err != nil {
		writeError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusCreated, view.NewUser(u))
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// POST /api/v1/auth/login
func (c *Controller) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !httpx.Decode(w, r, &req) {
		return
	}
	switch {
	case req.Email == "" || req.Password == "":
		httpx.Validation(w, "email and password are required")
		return
	case len(req.Email) > 254 || utf8.RuneCountInString(req.Password) > 128:
		httpx.Validation(w, "email or password too long")
		return
	}
	pair, err := c.svc.Login(r.Context(), req.Email, req.Password, userAgent(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeTokens(w, pair)
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// maxRefreshToken bounds the input; real tokens are 43 characters.
const maxRefreshToken = 512

func decodeRefreshToken(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req refreshTokenRequest
	if !httpx.Decode(w, r, &req) {
		return "", false
	}
	if req.RefreshToken == "" || len(req.RefreshToken) > maxRefreshToken {
		httpx.Validation(w, "refresh_token is required")
		return "", false
	}
	return req.RefreshToken, true
}

// POST /api/v1/auth/refresh
func (c *Controller) refresh(w http.ResponseWriter, r *http.Request) {
	token, ok := decodeRefreshToken(w, r)
	if !ok {
		return
	}
	pair, err := c.svc.Refresh(r.Context(), token, userAgent(r))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeTokens(w, pair)
}

// POST /api/v1/auth/logout: always 204 for a well-formed request.
func (c *Controller) logout(w http.ResponseWriter, r *http.Request) {
	token, ok := decodeRefreshToken(w, r)
	if !ok {
		return
	}
	if err := c.svc.Logout(r.Context(), token); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/v1/me
func (c *Controller) me(w http.ResponseWriter, r *http.Request) {
	id := identity(r.Context()).UserID
	if !isUUID(id) {
		httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid access token")
		return
	}
	u, err := c.svc.User(r.Context(), id)
	if errors.Is(err, model.ErrNotFound) {
		httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Unknown user")
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusOK, view.NewUser(u))
}

// GET /api/v1/admin/users?page=1&page_size=50&ids=<uuid>,<uuid>
func (c *Controller) listUsers(w http.ResponseWriter, r *http.Request) {
	page, ok := httpx.IntQuery(w, r, "page", 1, 1, 1_000_000)
	if !ok {
		return
	}
	pageSize, ok := httpx.IntQuery(w, r, "page_size", 50, 1, 100)
	if !ok {
		return
	}
	var ids []string
	if q := r.URL.Query(); q.Has("ids") {
		for _, id := range strings.Split(q.Get("ids"), ",") {
			id = strings.ToLower(strings.TrimSpace(id))
			if !isUUID(id) {
				httpx.Validation(w, "ids must be a comma-separated list of user ids")
				return
			}
			ids = append(ids, id)
		}
		if len(ids) > 100 {
			httpx.Validation(w, "ids accepts at most 100 user ids")
			return
		}
	}

	users, total, err := c.svc.ListUsers(r.Context(), model.UserFilter{Page: page, PageSize: pageSize, IDs: ids})
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusOK, view.NewUserPage(users, page, pageSize, total))
}

type userUpdateRequest struct {
	Role     *model.Role `json:"role"`
	IsActive *bool       `json:"is_active"`
}

// PATCH /api/v1/admin/users/{id}
func (c *Controller) updateUser(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(r.PathValue("id"))
	if !isUUID(id) {
		httpx.Validation(w, "id must be a user id (uuid)")
		return
	}
	var req userUpdateRequest
	if !httpx.Decode(w, r, &req) {
		return
	}
	u, err := c.svc.UpdateUser(r.Context(), identity(r.Context()).UserID, id,
		model.UserChanges{Role: req.Role, IsActive: req.IsActive})
	if err != nil {
		writeError(w, r, err)
		return
	}
	httpx.JSON(w, http.StatusOK, view.NewUser(u))
}

// Token responses must never be cached (RFC 6749, section 5.1).
func writeTokens(w http.ResponseWriter, pair service.TokenPair) {
	w.Header().Set("Cache-Control", "no-store")
	httpx.JSON(w, http.StatusOK, view.NewTokenPair(pair))
}

// userAgent is stored with the refresh token, to recognise sessions.
func userAgent(r *http.Request) string {
	ua := r.UserAgent()
	if len(ua) > 256 {
		ua = ua[:256]
	}
	if !utf8.ValidString(ua) {
		return ""
	}
	return ua
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isUUID(s string) bool { return uuidRE.MatchString(s) }
