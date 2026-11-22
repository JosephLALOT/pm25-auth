// Package model holds the users and refresh tokens of the auth schema and
// their PostgreSQL repositories. It is the only code that reads or writes
// the auth schema.
package model

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"pm25/auth/internal/audit"
)

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

func (r Role) Valid() bool { return r == RoleUser || r == RoleAdmin }

type User struct {
	ID           string
	Email        string
	PasswordHash string
	DisplayName  string
	Role         Role
	IsActive     bool
	CreatedAt    time.Time
	LastLoginAt  *time.Time
}

type NewUser struct {
	Email        string // already lower-case
	PasswordHash string
	DisplayName  string
	Role         Role
}

// UserChanges lists the fields to change; nil means unchanged.
type UserChanges struct {
	Role     *Role
	IsActive *bool
}

type UserFilter struct {
	Page     int      // from 1
	PageSize int      // 1 to 100
	IDs      []string // only these users when not empty
}

var (
	ErrNotFound     = errors.New("not found")
	ErrEmailTaken   = errors.New("e-mail already registered")
	ErrInvalidToken = errors.New("invalid refresh token")
)

type Users struct {
	pool *pgxpool.Pool
}

func NewUsers(pool *pgxpool.Pool) *Users { return &Users{pool: pool} }

// Ids are sent as text and cast in SQL, so pgx never has to guess the type.
const userColumns = `id::text, email, password_hash, display_name, role::text, is_active, created_at, last_login_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	var role string
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &role, &u.IsActive, &u.CreatedAt, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	u.Role = Role(role)
	return u, err
}

func (r *Users) Create(ctx context.Context, n NewUser) (User, error) {
	u, err := scanUser(r.pool.QueryRow(ctx,
		`INSERT INTO auth.user_account (email, password_hash, display_name, role)
		 VALUES ($1, $2, $3, $4::text::auth.user_role)
		 RETURNING `+userColumns,
		n.Email, n.PasswordHash, n.DisplayName, string(n.Role)))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation on email
		return User{}, ErrEmailTaken
	}
	return u, err
}

func (r *Users) ByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM auth.user_account WHERE email = $1`, email))
}

func (r *Users) ByID(ctx context.Context, id string) (User, error) {
	return scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM auth.user_account WHERE id = $1::text::uuid`, id))
}

// List returns one page of users, latest created first, and the total count.
func (r *Users) List(ctx context.Context, f UserFilter) ([]User, int, error) {
	ids := f.IDs
	if ids == nil {
		ids = []string{}
	}
	const where = ` WHERE coalesce(cardinality($1::text[]), 0) = 0 OR id = ANY($1::text[]::uuid[])`

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM auth.user_account`+where, ids).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx,
		`SELECT `+userColumns+` FROM auth.user_account`+where+
			` ORDER BY created_at DESC, id LIMIT $2 OFFSET $3`,
		ids, f.PageSize, (f.Page-1)*f.PageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

func (r *Users) RecordLogin(ctx context.Context, id string, at time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE auth.user_account SET last_login_at = $2 WHERE id = $1::text::uuid`, id, at)
	return err
}

// Update applies the changes made by the admin actorID. In the same
// transaction it writes one audit event per changed field and, when the user
// is deactivated, revokes their refresh tokens (so a later reactivation does
// not bring old sessions back).
func (r *Users) Update(ctx context.Context, actorID, id string, ch UserChanges, now time.Time) (User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	cur, err := scanUser(tx.QueryRow(ctx,
		`SELECT `+userColumns+` FROM auth.user_account WHERE id = $1::text::uuid FOR UPDATE`, id))
	if err != nil {
		return User{}, err
	}
	events := ChangeEvents(actorID, cur, ch)
	if len(events) == 0 {
		return cur, tx.Commit(ctx)
	}

	next := Apply(cur, ch)
	updated, err := scanUser(tx.QueryRow(ctx,
		`UPDATE auth.user_account SET role = $2::text::auth.user_role, is_active = $3
		 WHERE id = $1::text::uuid RETURNING `+userColumns,
		id, string(next.Role), next.IsActive))
	if err != nil {
		return User{}, err
	}
	if cur.IsActive && !next.IsActive {
		if _, err := tx.Exec(ctx,
			`UPDATE auth.refresh_token SET revoked_at = $2
			 WHERE user_id = $1::text::uuid AND revoked_at IS NULL`, id, now); err != nil {
			return User{}, err
		}
	}
	for _, e := range events {
		if err := audit.Write(ctx, tx, e); err != nil {
			return User{}, fmt.Errorf("audit: %w", err)
		}
	}
	return updated, tx.Commit(ctx)
}

// Apply returns u with the changes applied.
func Apply(u User, ch UserChanges) User {
	if ch.Role != nil {
		u.Role = *ch.Role
	}
	if ch.IsActive != nil {
		u.IsActive = *ch.IsActive
	}
	return u
}

// ChangeEvents lists the audit events of a change, one per field that
// really changes (none when the change is a no-op).
func ChangeEvents(actorID string, cur User, ch UserChanges) []audit.Event {
	next := Apply(cur, ch)
	var events []audit.Event
	if next.Role != cur.Role {
		events = append(events, audit.Event{
			UserID: actorID, Action: "user.role_change", TargetType: "user", TargetID: cur.ID,
			Details: map[string]any{"from": cur.Role, "to": next.Role},
		})
	}
	if next.IsActive != cur.IsActive {
		events = append(events, audit.Event{
			UserID: actorID, Action: "user.status_change", TargetType: "user", TargetID: cur.ID,
			Details: map[string]any{"is_active": next.IsActive},
		})
	}
	return events
}
