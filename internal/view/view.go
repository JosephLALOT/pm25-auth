// Package view holds the JSON representations of the contract
// (contracts/openapi.yaml). Optional fields are omitted, never null, and
// times are UTC without fractions of a second.
package view

import (
	"encoding/base64"
	"time"

	"pm25/auth/internal/model"
	"pm25/auth/internal/service"
)

type User struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	Role        model.Role `json:"role"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

func NewUser(u model.User) User {
	v := User{
		ID:          u.ID,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		Role:        u.Role,
		IsActive:    u.IsActive,
		CreatedAt:   utc(u.CreatedAt),
	}
	if u.LastLoginAt != nil {
		t := utc(*u.LastLoginAt)
		v.LastLoginAt = &t
	}
	return v
}

type UserPage struct {
	Items    []User `json:"items"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
	Total    int    `json:"total"`
}

func NewUserPage(users []model.User, page, pageSize, total int) UserPage {
	p := UserPage{Items: make([]User, 0, len(users)), Page: page, PageSize: pageSize, Total: total}
	for _, u := range users {
		p.Items = append(p.Items, NewUser(u))
	}
	return p
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func NewTokenPair(p service.TokenPair) TokenPair {
	return TokenPair{AccessToken: p.AccessToken, RefreshToken: p.RefreshToken, ExpiresIn: p.ExpiresIn}
}

type Health struct {
	Status   string `json:"status"` // ok or down
	Database struct {
		Reachable bool `json:"reachable"`
	} `json:"database"`
	KID string `json:"kid,omitempty"`
}

// JWK is an Ed25519 public key (RFC 8037).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	KID string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func NewJWKS(keys []service.PublicKey) JWKS {
	set := JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, k := range keys {
		set.Keys = append(set.Keys, JWK{
			Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(k.Key),
			KID: k.KID, Use: "sig", Alg: "EdDSA",
		})
	}
	return set
}

func utc(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }
