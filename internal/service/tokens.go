package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"pm25/auth/internal/model"
)

// TokenIssuer signs access tokens (EdDSA JWTs, ADR 0008) and verifies the
// ones sent back to pm25-auth (/me, /admin/*), with the same rules as the API.
type TokenIssuer struct {
	keys     *KeySet
	issuer   string
	audience string
	ttl      time.Duration
	now      func() time.Time
}

func NewTokenIssuer(keys *KeySet, issuer, audience string, ttl time.Duration) *TokenIssuer {
	return &TokenIssuer{keys: keys, issuer: issuer, audience: audience, ttl: ttl, now: time.Now}
}

func (t *TokenIssuer) TTL() time.Duration { return t.ttl }

// Identity is what an access token says about its bearer.
type Identity struct {
	UserID string
	Role   model.Role
}

var ErrTokenExpired = errors.New("access token expired")

// leeway tolerates small clock differences between services.
const leeway = 30 * time.Second

func (t *TokenIssuer) Issue(u model.User) (string, error) {
	now := t.now()
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss":  t.issuer,
		"aud":  t.audience, // a single string, as in the contract
		"sub":  u.ID,
		"role": string(u.Role),
		"iat":  now.Unix(),
		"exp":  now.Add(t.ttl).Unix(),
	})
	tok.Header["kid"] = t.keys.KID()
	return tok.SignedString(t.keys.private)
}

type accessClaims struct {
	jwt.RegisteredClaims
	Role model.Role `json:"role"`
}

// Verify checks the signature (EdDSA only, kid from the key set), iss, aud
// and exp, and returns the identity of the token.
func (t *TokenIssuer) Verify(raw string) (Identity, error) {
	c := &accessClaims{}
	_, err := jwt.ParseWithClaims(raw, c,
		func(tok *jwt.Token) (any, error) {
			kid, _ := tok.Header["kid"].(string)
			if key, ok := t.keys.PublicKey(kid); ok {
				return key, nil
			}
			return nil, fmt.Errorf("unknown kid %q", kid)
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(t.issuer),
		jwt.WithAudience(t.audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
		jwt.WithTimeFunc(t.now),
	)
	if errors.Is(err, jwt.ErrTokenExpired) {
		return Identity{}, ErrTokenExpired
	}
	if err != nil {
		return Identity{}, err
	}
	if c.Subject == "" || !c.Role.Valid() {
		return Identity{}, errors.New("access token without sub or with an unknown role")
	}
	return Identity{UserID: c.Subject, Role: c.Role}, nil
}

// newRefreshToken returns an opaque token (32 random bytes, base64url) and
// the SHA-256 that is stored instead of it.
func newRefreshToken() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	return token, hashRefreshToken(token), nil
}

func hashRefreshToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
