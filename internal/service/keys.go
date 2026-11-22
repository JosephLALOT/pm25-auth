package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// KeySet holds the active Ed25519 signing key and the public keys published
// in the JWKS: the active one first, then the previous ones still accepted
// during a rotation (ADR 0008).
type KeySet struct {
	kid     string
	private ed25519.PrivateKey
	public  []PublicKey
}

type PublicKey struct {
	KID string
	Key ed25519.PublicKey
}

// NewKeySet decodes JWT_SIGNING_KEY (base64 of the 32-byte seed),
// JWT_SIGNING_KID and JWT_PREVIOUS_PUBLIC_KEYS ("kid:base64,kid:base64").
// Standard and URL-safe base64 are both accepted, with or without padding.
func NewKeySet(seed, kid, previous string) (*KeySet, error) {
	raw, err := decodeBase64(seed)
	if err != nil || len(raw) != ed25519.SeedSize {
		return nil, fmt.Errorf("JWT_SIGNING_KEY must be the base64 of a %d-byte Ed25519 seed", ed25519.SeedSize)
	}
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return nil, errors.New("JWT_SIGNING_KID is required with JWT_SIGNING_KEY")
	}
	priv := ed25519.NewKeyFromSeed(raw)
	ks := &KeySet{
		kid:     kid,
		private: priv,
		public:  []PublicKey{{KID: kid, Key: priv.Public().(ed25519.PublicKey)}},
	}

	for _, entry := range strings.Split(previous, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		pkid, b64, ok := strings.Cut(entry, ":")
		pkid = strings.TrimSpace(pkid)
		if !ok || pkid == "" {
			return nil, fmt.Errorf("JWT_PREVIOUS_PUBLIC_KEYS: %q is not kid:base64", entry)
		}
		pub, err := decodeBase64(strings.TrimSpace(b64))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("JWT_PREVIOUS_PUBLIC_KEYS: key %q must be the base64 of a %d-byte Ed25519 public key",
				pkid, ed25519.PublicKeySize)
		}
		if _, dup := ks.PublicKey(pkid); dup {
			return nil, fmt.Errorf("JWT_PREVIOUS_PUBLIC_KEYS: kid %q is used twice", pkid)
		}
		ks.public = append(ks.public, PublicKey{KID: pkid, Key: ed25519.PublicKey(pub)})
	}
	return ks, nil
}

// EphemeralKeySet makes a random key that lives as long as the process, for
// local development when JWT_SIGNING_KEY is not set. Its kid starts with "dev-".
func EphemeralKeySet() (*KeySet, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return NewKeySet(base64.StdEncoding.EncodeToString(seed), "dev-"+hex.EncodeToString(seed[:4]), "")
}

func (k *KeySet) KID() string { return k.kid }

// Public lists the keys to publish in the JWKS, the active one first.
func (k *KeySet) Public() []PublicKey { return k.public }

func (k *KeySet) PublicKey(kid string) (ed25519.PublicKey, bool) {
	for _, p := range k.public {
		if p.KID == kid {
			return p.Key, true
		}
	}
	return nil, false
}

// GeneratedKey is printed by "pm25-auth signing-key generate".
type GeneratedKey struct {
	Seed      string // value of JWT_SIGNING_KEY (keep secret)
	PublicKey string // to put in JWT_PREVIOUS_PUBLIC_KEYS at the next rotation
	KID       string // suggested JWT_SIGNING_KID, e.g. 2026-11
}

func GenerateSigningKey(now time.Time) (GeneratedKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return GeneratedKey{}, err
	}
	return GeneratedKey{
		Seed:      base64.StdEncoding.EncodeToString(priv.Seed()),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		KID:       now.UTC().Format("2006-01"),
	}, nil
}

func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}
