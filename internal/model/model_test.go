package model

// Repository tests against PostgreSQL. They need TEST_DATABASE_URL, an empty
// throw-away database (the auth schema is dropped and created again), e.g.
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/pm25_test?sslmode=disable go test ./...

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Same table as in the public migrations of pm25-platform.
const auditTable = `
CREATE TABLE IF NOT EXISTS public.audit_event (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id     uuid,
  action      text NOT NULL,
  target_type text,
  target_id   text,
  details     jsonb,
  created_at  timestamptz NOT NULL DEFAULT now()
);
TRUNCATE public.audit_event;`

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set: PostgreSQL tests skipped")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	up, err := os.ReadFile("../../db/migrations/000001_auth_schema.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{`DROP SCHEMA IF EXISTS auth CASCADE`, string(up), auditTable} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}

func createUser(t *testing.T, users *Users, email string) User {
	t.Helper()
	u, err := users.Create(context.Background(), NewUser{Email: email, PasswordHash: "$argon2id$x", DisplayName: "Test", Role: RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestUsersCreateAndFind(t *testing.T) {
	pool := testPool(t)
	users := NewUsers(pool)
	ctx := context.Background()

	u := createUser(t, users, "an@example.com")
	if len(u.ID) != 36 || u.Role != RoleUser || !u.IsActive || u.LastLoginAt != nil || u.CreatedAt.IsZero() {
		t.Fatalf("created %+v", u)
	}
	if got, err := users.ByEmail(ctx, "an@example.com"); err != nil || got.ID != u.ID {
		t.Fatalf("ByEmail = %+v, %v", got, err)
	}
	if got, err := users.ByID(ctx, u.ID); err != nil || got.Email != u.Email {
		t.Fatalf("ByID = %+v, %v", got, err)
	}
	if _, err := users.ByID(ctx, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if _, err := users.Create(ctx, NewUser{Email: "an@example.com", PasswordHash: "h", DisplayName: "X", Role: RoleAdmin}); !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := users.Create(ctx, NewUser{Email: "Upper@example.com", PasswordHash: "h", DisplayName: "X", Role: RoleUser}); err == nil {
		t.Fatal("the lower-case check of the schema did not apply")
	}

	at := time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)
	if err := users.RecordLogin(ctx, u.ID, at); err != nil {
		t.Fatal(err)
	}
	if got, _ := users.ByID(ctx, u.ID); got.LastLoginAt == nil || !got.LastLoginAt.Equal(at) {
		t.Fatalf("last_login_at = %v", got.LastLoginAt)
	}
}

func TestUsersList(t *testing.T) {
	pool := testPool(t)
	users := NewUsers(pool)
	ctx := context.Background()
	a := createUser(t, users, "a@example.com")
	b := createUser(t, users, "b@example.com")
	c := createUser(t, users, "c@example.com")

	got, total, err := users.List(ctx, UserFilter{Page: 1, PageSize: 2})
	if err != nil || total != 3 || len(got) != 2 || got[0].ID != c.ID || got[1].ID != b.ID {
		t.Fatalf("page 1: %v, %d, %v", got, total, err)
	}
	got, total, _ = users.List(ctx, UserFilter{Page: 2, PageSize: 2})
	if total != 3 || len(got) != 1 || got[0].ID != a.ID {
		t.Fatalf("page 2: %v, %d", got, total)
	}
	got, total, _ = users.List(ctx, UserFilter{Page: 5, PageSize: 2})
	if total != 3 || got == nil || len(got) != 0 {
		t.Fatalf("page 5: %v, %d", got, total)
	}
	got, total, _ = users.List(ctx, UserFilter{Page: 1, PageSize: 50, IDs: []string{a.ID, c.ID, "00000000-0000-4000-8000-000000000000"}})
	if total != 2 || len(got) != 2 || got[0].ID != c.ID {
		t.Fatalf("ids: %v, %d", got, total)
	}
}

type auditRow struct {
	UserID, Action, TargetType, TargetID, Details string
}

func auditRows(t *testing.T, pool *pgxpool.Pool) []auditRow {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT user_id::text, action, target_type, target_id, details::text FROM public.audit_event ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.UserID, &r.Action, &r.TargetType, &r.TargetID, &r.Details); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestUsersUpdateWritesAuditAndRevokes(t *testing.T) {
	pool := testPool(t)
	users, tokens := NewUsers(pool), NewRefreshTokens(pool)
	ctx := context.Background()
	now := time.Now()
	admin := createUser(t, users, "admin@example.com")
	u := createUser(t, users, "an@example.com")
	if err := tokens.Create(ctx, NewRefreshToken{UserID: u.ID, Hash: []byte("token-1"), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	role := RoleAdmin
	got, err := users.Update(ctx, admin.ID, u.ID, UserChanges{Role: &role}, now)
	if err != nil || got.Role != RoleAdmin {
		t.Fatalf("promote: %+v, %v", got, err)
	}
	if _, err := users.Update(ctx, admin.ID, u.ID, UserChanges{Role: &role}, now); err != nil { // no-op
		t.Fatal(err)
	}
	off := false
	if got, err = users.Update(ctx, admin.ID, u.ID, UserChanges{IsActive: &off}, now); err != nil || got.IsActive {
		t.Fatalf("deactivate: %+v, %v", got, err)
	}
	if _, err := users.Update(ctx, admin.ID, "00000000-0000-4000-8000-000000000000", UserChanges{IsActive: &off}, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}

	want := []auditRow{
		{admin.ID, "user.role_change", "user", u.ID, `{"to": "admin", "from": "user"}`},
		{admin.ID, "user.status_change", "user", u.ID, `{"is_active": false}`},
	}
	if rows := auditRows(t, pool); len(rows) != len(want) || rows[0] != want[0] || rows[1] != want[1] {
		t.Fatalf("audit rows %+v", rows)
	}
	if _, err := tokens.Rotate(ctx, []byte("token-1"), NewRefreshToken{Hash: []byte("token-2"), ExpiresAt: now.Add(time.Hour)}, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("token of a deactivated user: %v", err)
	}
	var revoked bool
	_ = pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM auth.refresh_token WHERE token_hash = 'token-1'`).Scan(&revoked)
	if !revoked {
		t.Fatal("deactivation did not revoke the refresh token")
	}
}

func TestRefreshTokensRotate(t *testing.T) {
	pool := testPool(t)
	users, tokens := NewUsers(pool), NewRefreshTokens(pool)
	ctx := context.Background()
	now := time.Now()
	u := createUser(t, users, "an@example.com")
	next := func(h string) NewRefreshToken {
		return NewRefreshToken{Hash: []byte(h), UserAgent: "agent", ExpiresAt: now.Add(time.Hour)}
	}

	if err := tokens.Create(ctx, NewRefreshToken{UserID: u.ID, Hash: []byte("A"), ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, err := tokens.Rotate(ctx, []byte("A"), next("B"), now)
	if err != nil || got.ID != u.ID {
		t.Fatalf("A->B: %+v, %v", got, err)
	}
	if _, err := tokens.Rotate(ctx, []byte("A"), next("C"), now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("A reused: %v", err)
	}
	if _, err := tokens.Rotate(ctx, []byte("B"), next("C"), now); err != nil {
		t.Fatalf("B->C: %v", err)
	}
	if _, err := tokens.Rotate(ctx, []byte("nope"), next("D"), now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := tokens.Rotate(ctx, []byte("C"), next("D"), now.Add(2*time.Hour)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expired: %v", err)
	}

	var userAgent string
	var userID string
	_ = pool.QueryRow(ctx, `SELECT user_id::text, user_agent FROM auth.refresh_token WHERE token_hash = 'C'`).Scan(&userID, &userAgent)
	if userID != u.ID || userAgent != "agent" {
		t.Fatalf("rotated token stored for %q with agent %q", userID, userAgent)
	}
}

func TestRefreshTokensRevokeAndPurge(t *testing.T) {
	pool := testPool(t)
	users, tokens := NewUsers(pool), NewRefreshTokens(pool)
	ctx := context.Background()
	now := time.Now()
	u := createUser(t, users, "an@example.com")

	for h, exp := range map[string]time.Time{"live": now.Add(time.Hour), "old": now.Add(-8 * 24 * time.Hour), "recent": now.Add(-time.Hour)} {
		if err := tokens.Create(ctx, NewRefreshToken{UserID: u.ID, Hash: []byte(h), ExpiresAt: exp}); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := tokens.Revoke(ctx, []byte("live"), now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tokens.Rotate(ctx, []byte("live"), NewRefreshToken{Hash: []byte("x"), ExpiresAt: now.Add(time.Hour)}, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("revoked token rotated: %v", err)
	}

	n, err := tokens.Purge(ctx)
	if err != nil || n != 1 {
		t.Fatalf("purge = %d, %v (want only the token expired 8 days ago)", n, err)
	}
	var left [][]byte
	rows, _ := pool.Query(ctx, `SELECT token_hash FROM auth.refresh_token ORDER BY token_hash`)
	for rows.Next() {
		var h []byte
		_ = rows.Scan(&h)
		left = append(left, h)
	}
	rows.Close()
	if len(left) != 2 || !bytes.Equal(left[0], []byte("live")) || !bytes.Equal(left[1], []byte("recent")) {
		t.Fatalf("tokens left %q", left)
	}
}
