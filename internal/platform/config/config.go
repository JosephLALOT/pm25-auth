// Package config reads the configuration of pm25-auth from environment
// variables (ARCHITECTURE.md of pm25-platform, section 7).
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr    string
	DatabaseURL string
	DBMaxConns  int32

	// Signing keys as given in the environment, decoded by service.NewKeySet.
	SigningKey         string // base64 of the 32-byte Ed25519 seed; empty = development key
	SigningKID         string
	PreviousPublicKeys string // "kid:base64,kid:base64"

	Issuer     string
	Audience   string
	AccessTTL  time.Duration
	RefreshTTL time.Duration

	CORSOrigins []string

	RateLimitRPS   float64
	RateLimitBurst int
	// TrustProxy takes the client IP from X-Forwarded-For (set by the
	// alwaysdata proxy) instead of the TCP peer address.
	TrustProxy bool

	LogLevel string
}

func Load() (Config, error) {
	c := Config{
		HTTPAddr:           httpAddr(),
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		SigningKey:         os.Getenv("JWT_SIGNING_KEY"),
		SigningKID:         os.Getenv("JWT_SIGNING_KID"),
		PreviousPublicKeys: os.Getenv("JWT_PREVIOUS_PUBLIC_KEYS"),
		Issuer:             env("JWT_ISSUER", "http://localhost:8001"),
		Audience:           env("JWT_AUDIENCE", "pm25-api"),
		LogLevel:           env("LOG_LEVEL", "info"),
	}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL is required")
	}
	for _, o := range strings.Split(env("CORS_ORIGINS", "http://localhost:4200"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			c.CORSOrigins = append(c.CORSOrigins, o)
		}
	}

	var err error
	if c.DBMaxConns, err = envInt32("DB_MAX_CONNS", 3); err != nil {
		return c, err
	}
	if c.AccessTTL, err = envDuration("ACCESS_TOKEN_TTL", 15*time.Minute); err != nil {
		return c, err
	}
	if c.RefreshTTL, err = envDuration("REFRESH_TOKEN_TTL", 7*24*time.Hour); err != nil {
		return c, err
	}
	if c.RateLimitRPS, err = envFloat("RATE_LIMIT_RPS", 2); err != nil {
		return c, err
	}
	if c.RateLimitBurst, err = envInt("RATE_LIMIT_BURST", 10); err != nil {
		return c, err
	}
	if c.TrustProxy, err = envBool("TRUST_PROXY", false); err != nil {
		return c, err
	}

	switch {
	case c.DBMaxConns < 1:
		return c, fmt.Errorf("DB_MAX_CONNS must be at least 1")
	case c.AccessTTL <= 0 || c.RefreshTTL <= 0:
		return c, fmt.Errorf("ACCESS_TOKEN_TTL and REFRESH_TOKEN_TTL must be positive")
	case c.RateLimitRPS <= 0 || c.RateLimitBurst < 1:
		return c, fmt.Errorf("RATE_LIMIT_RPS must be positive and RATE_LIMIT_BURST at least 1")
	}
	return c, nil
}

// httpAddr uses HTTP_ADDR, or the $IP and $PORT given by an alwaysdata site.
func httpAddr() string {
	if v := os.Getenv("HTTP_ADDR"); v != "" {
		return v
	}
	if port := os.Getenv("PORT"); port != "" {
		return net.JoinHostPort(os.Getenv("IP"), port)
	}
	return ":8001"
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envInt32(key string, def int32) (int32, error) {
	n, err := envInt(key, int(def))
	return int32(n), err
}

func envFloat(key string, def float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return f, nil
}

func envBool(key string, def bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}
