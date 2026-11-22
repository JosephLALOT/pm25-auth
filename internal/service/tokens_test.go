package service

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"pm25/auth/internal/model"
)

const (
	testIssuer   = "https://pm25-auth.test"
	testAudience = "pm25-api"
)

var testNow = time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)

func testIssuerWithKeys(t *testing.T, previous string) (*TokenIssuer, *KeySet) {
	t.Helper()
	ks, err := NewKeySet(base64.StdEncoding.EncodeToString(seed(7)), "2026-11", previous)
	if err != nil {
		t.Fatal(err)
	}
	ti := NewTokenIssuer(ks, testIssuer, testAudience, 15*time.Minute)
	ti.now = func() time.Time { return testNow }
	return ti, ks
}

func segment(t *testing.T, raw string, i int) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[i])
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIssuedTokenMatchesContract(t *testing.T) {
	ti, _ := testIssuerWithKeys(t, "")
	raw, err := ti.Issue(model.User{ID: "3f1c2a9e-8b7d-4c1e-9a2b-6d5e4f3a2b1c", Role: model.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}

	h := segment(t, raw, 0)
	if h["alg"] != "EdDSA" || h["typ"] != "JWT" || h["kid"] != "2026-11" {
		t.Fatalf("header %v", h)
	}
	c := segment(t, raw, 1)
	want := map[string]any{
		"iss": testIssuer, "aud": testAudience, "sub": "3f1c2a9e-8b7d-4c1e-9a2b-6d5e4f3a2b1c", "role": "admin",
		"iat": float64(testNow.Unix()), "exp": float64(testNow.Add(15 * time.Minute).Unix()),
	}
	if len(c) != len(want) {
		t.Fatalf("claims %v", c)
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("claim %s = %v, want %v", k, c[k], v)
		}
	}

	id, err := ti.Verify(raw)
	if err != nil || id.UserID != "3f1c2a9e-8b7d-4c1e-9a2b-6d5e4f3a2b1c" || id.Role != model.RoleAdmin {
		t.Fatalf("Verify = %+v, %v", id, err)
	}
}

func sign(t *testing.T, method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func claims(over map[string]any) jwt.MapClaims {
	c := jwt.MapClaims{
		"iss": testIssuer, "aud": testAudience, "sub": "3f1c2a9e-8b7d-4c1e-9a2b-6d5e4f3a2b1c", "role": "user",
		"iat": testNow.Unix(), "exp": testNow.Add(15 * time.Minute).Unix(),
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	oldPriv := ed25519.NewKeyFromSeed(seed(9))
	oldPub := base64.StdEncoding.EncodeToString(oldPriv.Public().(ed25519.PublicKey))
	ti, ks := testIssuerWithKeys(t, "2026-05:"+oldPub)
	active := ks.private
	activePub, _ := ks.PublicKey("2026-11")
	other := ed25519.NewKeyFromSeed(seed(42))

	cases := map[string]string{
		"alg none":            sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, "2026-11", claims(nil)),
		"HS256 public key":    sign(t, jwt.SigningMethodHS256, []byte(activePub), "2026-11", claims(nil)),
		"unknown kid":         sign(t, jwt.SigningMethodEdDSA, active, "2030-01", claims(nil)),
		"missing kid":         sign(t, jwt.SigningMethodEdDSA, active, "", claims(nil)),
		"other key same kid":  sign(t, jwt.SigningMethodEdDSA, other, "2026-11", claims(nil)),
		"wrong issuer":        sign(t, jwt.SigningMethodEdDSA, active, "2026-11", claims(map[string]any{"iss": "https://evil.test"})),
		"wrong audience":      sign(t, jwt.SigningMethodEdDSA, active, "2026-11", claims(map[string]any{"aud": "other-api"})),
		"no expiry":           sign(t, jwt.SigningMethodEdDSA, active, "2026-11", claims(map[string]any{"exp": nil})),
		"expired past leeway": sign(t, jwt.SigningMethodEdDSA, active, "2026-11", claims(map[string]any{"exp": testNow.Add(-31 * time.Second).Unix()})),
		"no subject":          sign(t, jwt.SigningMethodEdDSA, active, "2026-11", claims(map[string]any{"sub": nil})),
		"unknown role":        sign(t, jwt.SigningMethodEdDSA, active, "2026-11", claims(map[string]any{"role": "root"})),
		"garbage":             "not.a.jwt",
	}
	for name, raw := range cases {
		if _, err := ti.Verify(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	expired := sign(t, jwt.SigningMethodEdDSA, active, "2026-11", claims(map[string]any{"exp": testNow.Add(-time.Minute).Unix()}))
	if _, err := ti.Verify(expired); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired token: err = %v, want ErrTokenExpired", err)
	}

	accepted := map[string]string{
		"within leeway":    sign(t, jwt.SigningMethodEdDSA, active, "2026-11", claims(map[string]any{"exp": testNow.Add(-20 * time.Second).Unix()})),
		"previous key":     sign(t, jwt.SigningMethodEdDSA, oldPriv, "2026-05", claims(nil)),
		"audience as list": sign(t, jwt.SigningMethodEdDSA, active, "2026-11", claims(map[string]any{"aud": []string{"pm25-api"}})),
	}
	for name, raw := range accepted {
		if _, err := ti.Verify(raw); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
}

func TestRefreshTokenFormat(t *testing.T) {
	a, hashA, err := newRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := newRefreshToken()
	if len(a) != 43 || a == b {
		t.Fatalf("tokens %q, %q", a, b)
	}
	if string(hashRefreshToken(a)) != string(hashA) || len(hashA) != 32 {
		t.Fatal("stored hash is not the SHA-256 of the token")
	}
}
