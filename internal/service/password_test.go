package service

import (
	"regexp"
	"testing"
)

// testHasher is cheap, so the tests stay fast; DefaultHasher is tested once.
var testHasher = Hasher{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func TestHashFormatAndVerify(t *testing.T) {
	hash, err := DefaultHasher.Hash("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	phc := regexp.MustCompile(`^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)
	if !phc.MatchString(hash) {
		t.Fatalf("unexpected PHC string %q", hash)
	}
	if ok, err := DefaultHasher.Verify("correct-horse-battery", hash); err != nil || !ok {
		t.Fatalf("Verify(right password) = %v, %v", ok, err)
	}
	if ok, err := DefaultHasher.Verify("correct-horse-batterY", hash); err != nil || ok {
		t.Fatalf("Verify(wrong password) = %v, %v", ok, err)
	}
}

func TestHashUsesRandomSalt(t *testing.T) {
	a, _ := testHasher.Hash("same password")
	b, _ := testHasher.Hash("same password")
	if a == b {
		t.Fatal("two hashes of the same password are equal")
	}
}

func TestVerifyReadsParametersFromHash(t *testing.T) {
	hash, _ := testHasher.Hash("a long password")
	// A hasher with other parameters still verifies old hashes.
	if ok, err := DefaultHasher.Verify("a long password", hash); err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	for _, h := range []string{
		"",
		"plain",
		"$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaA",
		"$argon2id$v=18$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaA",
		"$argon2id$v=19$m=0,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaA",
		"$argon2id$v=19$m=64,t=1,p=1$!!!$aGFzaA",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0$",
	} {
		if _, err := testHasher.Verify("password", h); err == nil {
			t.Errorf("Verify(%q) accepted a malformed hash", h)
		}
	}
}
