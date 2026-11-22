package model

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type NewRefreshToken struct {
	UserID    string
	Hash      []byte // SHA-256 of the token sent to the client
	UserAgent string
	ExpiresAt time.Time
}

type RefreshTokens struct {
	pool *pgxpool.Pool
}

func NewRefreshTokens(pool *pgxpool.Pool) *RefreshTokens { return &RefreshTokens{pool: pool} }

func (r *RefreshTokens) Create(ctx context.Context, t NewRefreshToken) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO auth.refresh_token (user_id, token_hash, user_agent, expires_at)
		 VALUES ($1::text::uuid, $2, NULLIF($3::text, ''), $4)`,
		t.UserID, t.Hash, t.UserAgent, t.ExpiresAt)
	return err
}

// Rotate revokes the refresh token with hash oldHash and stores next for the
// same user, in one transaction. It fails with ErrInvalidToken when the token
// is unknown, revoked or expired, or when its user is inactive. next.UserID
// is ignored. Returns the user as stored now (current role).
//
// Locks are taken user first, then token, in the same order as Users.Update,
// so a refresh and a deactivation of the same user cannot deadlock.
func (r *RefreshTokens) Rotate(ctx context.Context, oldHash []byte, next NewRefreshToken, now time.Time) (User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	err = tx.QueryRow(ctx,
		`SELECT user_id::text FROM auth.refresh_token WHERE token_hash = $1`, oldHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrInvalidToken
	}
	if err != nil {
		return User{}, err
	}

	u, err := scanUser(tx.QueryRow(ctx,
		`SELECT `+userColumns+` FROM auth.user_account WHERE id = $1::text::uuid FOR SHARE`, userID))
	if err != nil {
		return User{}, err
	}

	var tokenID string
	var expiresAt time.Time
	var revoked bool
	err = tx.QueryRow(ctx,
		`SELECT id::text, expires_at, revoked_at IS NOT NULL
		 FROM auth.refresh_token WHERE token_hash = $1 FOR UPDATE`, oldHash).Scan(&tokenID, &expiresAt, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrInvalidToken
	}
	if err != nil {
		return User{}, err
	}
	if revoked || !now.Before(expiresAt) || !u.IsActive {
		return User{}, ErrInvalidToken
	}

	if _, err := tx.Exec(ctx,
		`UPDATE auth.refresh_token SET revoked_at = $2 WHERE id = $1::text::uuid`, tokenID, now); err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO auth.refresh_token (user_id, token_hash, user_agent, expires_at)
		 VALUES ($1::text::uuid, $2, NULLIF($3::text, ''), $4)`,
		u.ID, next.Hash, next.UserAgent, next.ExpiresAt); err != nil {
		return User{}, err
	}
	return u, tx.Commit(ctx)
}

// Revoke revokes the token if it exists and is not revoked yet.
func (r *RefreshTokens) Revoke(ctx context.Context, hash []byte, now time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE auth.refresh_token SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL`, hash, now)
	return err
}

// Purge deletes the tokens expired for more than 7 days (auth.purge_expired_tokens).
func (r *RefreshTokens) Purge(ctx context.Context) (int64, error) {
	var n int64
	err := r.pool.QueryRow(ctx, `SELECT auth.purge_expired_tokens()`).Scan(&n)
	return n, err
}
