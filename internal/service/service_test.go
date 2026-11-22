package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"pm25/auth/internal/memstore"
	"pm25/auth/internal/model"
)

type fixture struct {
	svc   *Service
	store *memstore.Store
	now   *time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ti, _ := testIssuerWithKeys(t, "")
	store := memstore.New()
	svc := New(store.Users(), store.Tokens(), ti, testHasher, 7*24*time.Hour)
	now := testNow
	clock := func() time.Time { return now }
	svc.now, ti.now = clock, clock
	return fixture{svc: svc, store: store, now: &now}
}

func (f fixture) register(t *testing.T, email string) model.User {
	t.Helper()
	u, err := f.svc.Register(context.Background(), email, "correct-horse-battery", "Test User")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (f fixture) login(t *testing.T, email string) TokenPair {
	t.Helper()
	p, err := f.svc.Login(context.Background(), email, "correct-horse-battery", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func isValidation(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}

func TestRegister(t *testing.T) {
	f := newFixture(t)
	u := f.register(t, "  An.Nguyen@Example.COM ")
	if u.Email != "an.nguyen@example.com" || u.Role != model.RoleUser || !u.IsActive || u.LastLoginAt != nil {
		t.Fatalf("created %+v", u)
	}
	if ok, _ := testHasher.Verify("correct-horse-battery", u.PasswordHash); !ok {
		t.Fatal("password hash does not verify")
	}
	_, err := f.svc.Register(context.Background(), "AN.NGUYEN@example.com", "another-password", "Someone")
	if !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("duplicate e-mail: err = %v", err)
	}
}

func TestRegisterValidation(t *testing.T) {
	f := newFixture(t)
	cases := map[string][3]string{ // email, password, display name
		"empty email":       {"", "correct-horse-battery", "A"},
		"not an email":      {"not-an-email", "correct-horse-battery", "A"},
		"email with name":   {"An <an@example.com>", "correct-horse-battery", "A"},
		"email too long":    {strings.Repeat("a", 250) + "@x.io", "correct-horse-battery", "A"},
		"password 9 chars":  {"a@example.com", "123456789", "A"},
		"password 129":      {"a@example.com", strings.Repeat("p", 129), "A"},
		"empty name":        {"a@example.com", "correct-horse-battery", "   "},
		"name too long":     {"a@example.com", "correct-horse-battery", strings.Repeat("n", 65)},
		"name with control": {"a@example.com", "correct-horse-battery", "An\nNguyen"},
	}
	for name, c := range cases {
		if _, err := f.svc.Register(context.Background(), c[0], c[1], c[2]); !isValidation(err) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
	// Lengths count characters, not bytes.
	if _, err := f.svc.Register(context.Background(), "b@example.com", "пароль1234", strings.Repeat("я", 64)); err != nil {
		t.Errorf("10-character Cyrillic password: %v", err)
	}
}

func TestLogin(t *testing.T) {
	f := newFixture(t)
	u := f.register(t, "an@example.com")

	p := f.login(t, "AN@example.com")
	if p.ExpiresIn != 900 || p.AccessToken == "" || len(p.RefreshToken) != 43 {
		t.Fatalf("pair %+v", p)
	}
	id, err := f.svc.issuer.Verify(p.AccessToken)
	if err != nil || id.UserID != u.ID || id.Role != model.RoleUser {
		t.Fatalf("access token identity %+v, %v", id, err)
	}
	if got, _ := f.svc.User(context.Background(), u.ID); got.LastLoginAt == nil || !got.LastLoginAt.Equal(testNow) {
		t.Fatalf("last_login_at = %v", got.LastLoginAt)
	}
	if n := f.store.ActiveTokens(u.ID, *f.now); n != 1 {
		t.Fatalf("%d active refresh tokens, want 1", n)
	}
}

func TestLoginFailuresLookTheSame(t *testing.T) {
	f := newFixture(t)
	u := f.register(t, "an@example.com")
	f.register(t, "off@example.com")
	f.store.SetActive(mustUser(t, f, "off@example.com").ID, false)

	for name, c := range map[string][2]string{
		"wrong password": {"an@example.com", "wrong-password!"},
		"unknown e-mail": {"nobody@example.com", "correct-horse-battery"},
		"inactive":       {"off@example.com", "correct-horse-battery"},
	} {
		if _, err := f.svc.Login(context.Background(), c[0], c[1], ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if got, _ := f.svc.User(context.Background(), u.ID); got.LastLoginAt != nil {
		t.Fatal("a failed login updated last_login_at")
	}
}

func mustUser(t *testing.T, f fixture, email string) model.User {
	t.Helper()
	u, err := f.store.Users().ByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestRefreshRotatesTheToken(t *testing.T) {
	f := newFixture(t)
	u := f.register(t, "an@example.com")
	first := f.login(t, "an@example.com")

	second, err := f.svc.Refresh(context.Background(), first.RefreshToken, "")
	if err != nil {
		t.Fatal(err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token not rotated")
	}
	if _, err := f.svc.Refresh(context.Background(), first.RefreshToken, ""); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("old refresh token: err = %v", err)
	}
	if _, err := f.svc.Refresh(context.Background(), second.RefreshToken, ""); err != nil {
		t.Fatalf("new refresh token: %v", err)
	}
	if n := f.store.ActiveTokens(u.ID, *f.now); n != 1 {
		t.Fatalf("%d active refresh tokens, want 1", n)
	}
}

func TestRefreshCarriesTheCurrentRole(t *testing.T) {
	f := newFixture(t)
	admin, _ := f.svc.CreateAdmin(context.Background(), "admin@example.com", "correct-horse-battery", "Admin")
	u := f.register(t, "an@example.com")
	p := f.login(t, "an@example.com")

	role := model.RoleAdmin
	if _, err := f.svc.UpdateUser(context.Background(), admin.ID, u.ID, model.UserChanges{Role: &role}); err != nil {
		t.Fatal(err)
	}
	p, err := f.svc.Refresh(context.Background(), p.RefreshToken, "")
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := f.svc.issuer.Verify(p.AccessToken); id.Role != model.RoleAdmin {
		t.Fatalf("role after refresh = %q", id.Role)
	}
}

func TestRefreshRejectsExpiredAndInactive(t *testing.T) {
	f := newFixture(t)
	f.register(t, "an@example.com")
	p := f.login(t, "an@example.com")

	*f.now = testNow.Add(7 * 24 * time.Hour)
	if _, err := f.svc.Refresh(context.Background(), p.RefreshToken, ""); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expired: err = %v", err)
	}

	*f.now = testNow
	p = f.login(t, "an@example.com")
	f.store.SetActive(mustUser(t, f, "an@example.com").ID, false)
	if _, err := f.svc.Refresh(context.Background(), p.RefreshToken, ""); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("inactive: err = %v", err)
	}
	if _, err := f.svc.Refresh(context.Background(), "never-issued", ""); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("unknown: err = %v", err)
	}
}

func TestDeactivationEndsSessions(t *testing.T) {
	f := newFixture(t)
	admin, _ := f.svc.CreateAdmin(context.Background(), "admin@example.com", "correct-horse-battery", "Admin")
	u := f.register(t, "an@example.com")
	p := f.login(t, "an@example.com")

	off, on := false, true
	if _, err := f.svc.UpdateUser(context.Background(), admin.ID, u.ID, model.UserChanges{IsActive: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.UpdateUser(context.Background(), admin.ID, u.ID, model.UserChanges{IsActive: &on}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Refresh(context.Background(), p.RefreshToken, ""); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("session survived a deactivation: err = %v", err)
	}
	if len(f.store.Events) != 2 || f.store.Events[0].Action != "user.status_change" || f.store.Events[0].UserID != admin.ID {
		t.Fatalf("audit events %+v", f.store.Events)
	}
}

func TestLogout(t *testing.T) {
	f := newFixture(t)
	f.register(t, "an@example.com")
	p := f.login(t, "an@example.com")

	for range 2 { // idempotent
		if err := f.svc.Logout(context.Background(), p.RefreshToken); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.svc.Logout(context.Background(), "never-issued"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Refresh(context.Background(), p.RefreshToken, ""); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("refresh after logout: err = %v", err)
	}
}

func TestUpdateUserRules(t *testing.T) {
	f := newFixture(t)
	admin, _ := f.svc.CreateAdmin(context.Background(), "admin@example.com", "correct-horse-battery", "Admin")
	u := f.register(t, "an@example.com")
	ctx := context.Background()
	admin2, user, root := model.RoleAdmin, model.RoleUser, model.Role("root")
	off := false

	if _, err := f.svc.UpdateUser(ctx, admin.ID, admin.ID, model.UserChanges{IsActive: &off}); !errors.Is(err, ErrSelfUpdate) {
		t.Errorf("self update: err = %v", err)
	}
	if _, err := f.svc.UpdateUser(ctx, admin.ID, u.ID, model.UserChanges{}); !isValidation(err) {
		t.Errorf("empty change: err = %v", err)
	}
	if _, err := f.svc.UpdateUser(ctx, admin.ID, u.ID, model.UserChanges{Role: &root}); !isValidation(err) {
		t.Errorf("unknown role: err = %v", err)
	}
	if _, err := f.svc.UpdateUser(ctx, admin.ID, "00000000-0000-4000-8000-000000000000", model.UserChanges{Role: &admin2}); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown user: err = %v", err)
	}

	if _, err := f.svc.UpdateUser(ctx, admin.ID, u.ID, model.UserChanges{Role: &user}); err != nil {
		t.Fatal(err)
	}
	if len(f.store.Events) != 0 {
		t.Fatalf("a no-op change was audited: %+v", f.store.Events)
	}
	got, err := f.svc.UpdateUser(ctx, admin.ID, u.ID, model.UserChanges{Role: &admin2})
	if err != nil || got.Role != model.RoleAdmin {
		t.Fatalf("promote: %+v, %v", got, err)
	}
	e := f.store.Events
	if len(e) != 1 || e[0].Action != "user.role_change" || e[0].TargetID != u.ID ||
		e[0].Details["from"] != model.RoleUser || e[0].Details["to"] != model.RoleAdmin {
		t.Fatalf("audit events %+v", e)
	}
}
