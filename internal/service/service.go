// Package service holds the rules of pm25-auth: registration, login,
// refresh-token rotation, logout, user administration, signing keys and the
// JWKS. It depends on stores (interfaces) implemented by the model package,
// and by memstore in tests.
package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"pm25/auth/internal/model"
)

type UserStore interface {
	Create(ctx context.Context, u model.NewUser) (model.User, error)
	ByEmail(ctx context.Context, email string) (model.User, error)
	ByID(ctx context.Context, id string) (model.User, error)
	List(ctx context.Context, f model.UserFilter) ([]model.User, int, error)
	RecordLogin(ctx context.Context, id string, at time.Time) error
	Update(ctx context.Context, actorID, id string, ch model.UserChanges, now time.Time) (model.User, error)
}

type RefreshTokenStore interface {
	Create(ctx context.Context, t model.NewRefreshToken) error
	Rotate(ctx context.Context, oldHash []byte, next model.NewRefreshToken, now time.Time) (model.User, error)
	Revoke(ctx context.Context, hash []byte, now time.Time) error
}

var (
	ErrInvalidCredentials  = errors.New("invalid e-mail or password")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrEmailTaken          = model.ErrEmailTaken
	ErrUserNotFound        = model.ErrNotFound
	ErrSelfUpdate          = errors.New("an admin cannot change their own role or status")
)

// ValidationError is a client error, answered with 400 VALIDATION_ERROR.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int // seconds
}

type Service struct {
	users      UserStore
	tokens     RefreshTokenStore
	issuer     *TokenIssuer
	hasher     Hasher
	refreshTTL time.Duration
	now        func() time.Time

	dummyOnce sync.Once
	dummyHash string
}

func New(users UserStore, tokens RefreshTokenStore, issuer *TokenIssuer, hasher Hasher, refreshTTL time.Duration) *Service {
	return &Service{users: users, tokens: tokens, issuer: issuer, hasher: hasher, refreshTTL: refreshTTL, now: time.Now}
}

// Register creates an account with the role user.
func (s *Service) Register(ctx context.Context, email, password, displayName string) (model.User, error) {
	return s.create(ctx, email, password, displayName, model.RoleUser)
}

// CreateAdmin creates an admin account (command create-admin, never the API).
func (s *Service) CreateAdmin(ctx context.Context, email, password, displayName string) (model.User, error) {
	return s.create(ctx, email, password, displayName, model.RoleAdmin)
}

func (s *Service) create(ctx context.Context, email, password, displayName string, role model.Role) (model.User, error) {
	email = NormalizeEmail(email)
	displayName = strings.TrimSpace(displayName)
	if err := validateEmail(email); err != nil {
		return model.User{}, err
	}
	if err := ValidatePassword(password); err != nil {
		return model.User{}, err
	}
	if err := validateDisplayName(displayName); err != nil {
		return model.User{}, err
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return model.User{}, err
	}
	return s.users.Create(ctx, model.NewUser{Email: email, PasswordHash: hash, DisplayName: displayName, Role: role})
}

// Login checks the credentials and returns a new token pair. Unknown e-mail,
// wrong password and inactive account give the same error, and an unknown
// e-mail still costs one hash, so neither the answer nor its timing tells
// which accounts exist.
func (s *Service) Login(ctx context.Context, email, password, userAgent string) (TokenPair, error) {
	u, err := s.users.ByEmail(ctx, NormalizeEmail(email))
	if errors.Is(err, model.ErrNotFound) {
		_, _ = s.hasher.Verify(password, s.dummy())
		return TokenPair{}, ErrInvalidCredentials
	}
	if err != nil {
		return TokenPair{}, err
	}
	ok, err := s.hasher.Verify(password, u.PasswordHash)
	if err != nil {
		return TokenPair{}, fmt.Errorf("user %s: %w", u.ID, err)
	}
	if !ok || !u.IsActive {
		return TokenPair{}, ErrInvalidCredentials
	}

	now := s.now()
	if err := s.users.RecordLogin(ctx, u.ID, now); err != nil {
		return TokenPair{}, err
	}
	refresh, hash, err := newRefreshToken()
	if err != nil {
		return TokenPair{}, err
	}
	if err := s.tokens.Create(ctx, model.NewRefreshToken{
		UserID: u.ID, Hash: hash, UserAgent: userAgent, ExpiresAt: now.Add(s.refreshTTL),
	}); err != nil {
		return TokenPair{}, err
	}
	return s.pair(u, refresh)
}

// Refresh revokes the refresh token sent and returns a new pair. The access
// token carries the role stored now, so role changes apply here.
func (s *Service) Refresh(ctx context.Context, refreshToken, userAgent string) (TokenPair, error) {
	now := s.now()
	next, hash, err := newRefreshToken()
	if err != nil {
		return TokenPair{}, err
	}
	u, err := s.tokens.Rotate(ctx, hashRefreshToken(refreshToken), model.NewRefreshToken{
		Hash: hash, UserAgent: userAgent, ExpiresAt: now.Add(s.refreshTTL),
	}, now)
	if errors.Is(err, model.ErrInvalidToken) {
		return TokenPair{}, ErrInvalidRefreshToken
	}
	if err != nil {
		return TokenPair{}, err
	}
	return s.pair(u, next)
}

// Logout revokes the refresh token; unknown or revoked tokens are not an error.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	return s.tokens.Revoke(ctx, hashRefreshToken(refreshToken), s.now())
}

func (s *Service) User(ctx context.Context, id string) (model.User, error) {
	return s.users.ByID(ctx, id)
}

func (s *Service) ListUsers(ctx context.Context, f model.UserFilter) ([]model.User, int, error) {
	return s.users.List(ctx, f)
}

// UpdateUser changes the role or status of a user, on behalf of the admin
// actorID. An admin cannot change their own account, so the last admin can
// never lock everyone out.
func (s *Service) UpdateUser(ctx context.Context, actorID, id string, ch model.UserChanges) (model.User, error) {
	if ch.Role == nil && ch.IsActive == nil {
		return model.User{}, invalid("send at least one of role, is_active")
	}
	if ch.Role != nil && !ch.Role.Valid() {
		return model.User{}, invalid("role must be user or admin")
	}
	if actorID == id {
		return model.User{}, ErrSelfUpdate
	}
	return s.users.Update(ctx, actorID, id, ch, s.now())
}

func (s *Service) pair(u model.User, refresh string) (TokenPair, error) {
	access, err := s.issuer.Issue(u)
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{AccessToken: access, RefreshToken: refresh, ExpiresIn: int(s.issuer.TTL().Seconds())}, nil
}

// dummy is a hash of a random value, verified when the e-mail is unknown.
func (s *Service) dummy() string {
	s.dummyOnce.Do(func() {
		token, _, _ := newRefreshToken()
		s.dummyHash, _ = s.hasher.Hash(token)
	})
	return s.dummyHash
}

// ---- input rules (contract: RegisterRequest)

func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func validateEmail(email string) error {
	if email == "" {
		return invalid("email is required")
	}
	if len(email) > 254 {
		return invalid("email must be at most 254 characters")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || addr.Name != "" {
		return invalid("email is not a valid e-mail address")
	}
	return nil
}

// ValidatePassword applies the length rule: 10 to 128 characters.
func ValidatePassword(password string) error {
	n := utf8.RuneCountInString(password)
	if n < 10 {
		return invalid("password must be at least 10 characters")
	}
	if n > 128 {
		return invalid("password must be at most 128 characters")
	}
	return nil
}

func validateDisplayName(name string) error {
	n := utf8.RuneCountInString(name)
	if n == 0 {
		return invalid("display_name is required")
	}
	if n > 64 {
		return invalid("display_name must be at most 64 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return invalid("display_name must not contain control characters")
		}
	}
	return nil
}
