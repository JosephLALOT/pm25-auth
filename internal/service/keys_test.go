package service

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, ed25519.SeedSize) }

func TestNewKeySetAcceptsBase64Variants(t *testing.T) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		ks, err := NewKeySet(enc.EncodeToString(seed(0xfb)), "2026-11", "")
		if err != nil {
			t.Fatalf("%v: %v", enc, err)
		}
		want := ed25519.NewKeyFromSeed(seed(0xfb)).Public().(ed25519.PublicKey)
		if got, ok := ks.PublicKey("2026-11"); !ok || !got.Equal(want) {
			t.Fatal("active public key not published")
		}
	}
}

func TestNewKeySetErrors(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(seed(1))
	prev := base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed(2)).Public().(ed25519.PublicKey))
	cases := map[string]struct{ seed, kid, previous string }{
		"empty seed":         {"", "k", ""},
		"short seed":         {base64.StdEncoding.EncodeToString([]byte("short")), "k", ""},
		"not base64":         {"%%%", "k", ""},
		"missing kid":        {good, " ", ""},
		"previous no colon":  {good, "k", prev},
		"previous empty kid": {good, "k", ":" + prev},
		"previous bad key":   {good, "k", "old:" + base64.StdEncoding.EncodeToString([]byte("short"))},
		"previous same kid":  {good, "k", "k:" + prev},
		"previous twice":     {good, "k", "old:" + prev + ",old:" + prev},
	}
	for name, c := range cases {
		if _, err := NewKeySet(c.seed, c.kid, c.previous); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestKeySetPublishesActiveThenPrevious(t *testing.T) {
	gen1, _ := GenerateSigningKey(time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
	gen2, _ := GenerateSigningKey(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	if gen1.KID != "2026-05" || gen2.KID != "2026-11" {
		t.Fatalf("suggested kids %q, %q", gen1.KID, gen2.KID)
	}

	ks, err := NewKeySet(gen2.Seed, gen2.KID, " "+gen1.KID+":"+gen1.PublicKey+" , ")
	if err != nil {
		t.Fatal(err)
	}
	var kids []string
	for _, p := range ks.Public() {
		kids = append(kids, p.KID)
	}
	if strings.Join(kids, ",") != "2026-11,2026-05" {
		t.Fatalf("published kids %v", kids)
	}
	old, _ := base64.StdEncoding.DecodeString(gen1.PublicKey)
	if got, ok := ks.PublicKey("2026-05"); !ok || !got.Equal(ed25519.PublicKey(old)) {
		t.Fatal("previous key not published")
	}
	if ks.KID() != "2026-11" {
		t.Fatalf("active kid %q", ks.KID())
	}
}

func TestEphemeralKeySet(t *testing.T) {
	a, err := EphemeralKeySet()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := EphemeralKeySet()
	if !strings.HasPrefix(a.KID(), "dev-") || a.KID() == b.KID() {
		t.Fatalf("kids %q and %q", a.KID(), b.KID())
	}
}
