// Package memstore implements the stores of the service in memory, with the
// same rules as the PostgreSQL repositories of the model package. It is used
// by the unit tests of the service and the controllers; the repositories
// themselves are tested against PostgreSQL in internal/model.
package memstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"sync"
	"time"

	"pm25/auth/internal/audit"
	"pm25/auth/internal/model"
)

type Store struct {
	mu     sync.Mutex
	users  []model.User // in creation order
	tokens []token
	Events []audit.Event
	now    func() time.Time
}

type token struct {
	model.NewRefreshToken
	RevokedAt *time.Time
}

func New() *Store { return &Store{now: time.Now} }

// Users and Tokens expose the store through the two interfaces of the service.
func (s *Store) Users() *Users   { return (*Users)(s) }
func (s *Store) Tokens() *Tokens { return (*Tokens)(s) }

type Users Store
type Tokens Store

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (s *Users) Create(_ context.Context, n model.NewUser) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Email == n.Email {
			return model.User{}, model.ErrEmailTaken
		}
	}
	u := model.User{
		ID: newID(), Email: n.Email, PasswordHash: n.PasswordHash, DisplayName: n.DisplayName,
		Role: n.Role, IsActive: true, CreatedAt: s.now(),
	}
	s.users = append(s.users, u)
	return u, nil
}

func (s *Users) find(match func(model.User) bool) (int, bool) {
	for i, u := range s.users {
		if match(u) {
			return i, true
		}
	}
	return -1, false
}

func (s *Users) ByEmail(_ context.Context, email string) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i, ok := s.find(func(u model.User) bool { return u.Email == email }); ok {
		return s.users[i], nil
	}
	return model.User{}, model.ErrNotFound
}

func (s *Users) ByID(_ context.Context, id string) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i, ok := s.find(func(u model.User) bool { return u.ID == id }); ok {
		return s.users[i], nil
	}
	return model.User{}, model.ErrNotFound
}

func (s *Users) List(_ context.Context, f model.UserFilter) ([]model.User, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []model.User
	for i := len(s.users) - 1; i >= 0; i-- { // latest created first
		if len(f.IDs) == 0 || slices.Contains(f.IDs, s.users[i].ID) {
			all = append(all, s.users[i])
		}
	}
	start := min((f.Page-1)*f.PageSize, len(all))
	end := min(start+f.PageSize, len(all))
	return append([]model.User{}, all[start:end]...), len(all), nil
}

func (s *Users) RecordLogin(_ context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i, ok := s.find(func(u model.User) bool { return u.ID == id }); ok {
		s.users[i].LastLoginAt = &at
	}
	return nil
}

func (s *Users) Update(_ context.Context, actorID, id string, ch model.UserChanges, now time.Time) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.find(func(u model.User) bool { return u.ID == id })
	if !ok {
		return model.User{}, model.ErrNotFound
	}
	cur := s.users[i]
	events := model.ChangeEvents(actorID, cur, ch)
	if len(events) == 0 {
		return cur, nil
	}
	next := model.Apply(cur, ch)
	s.users[i] = next
	if cur.IsActive && !next.IsActive {
		for j := range s.tokens {
			if s.tokens[j].UserID == id && s.tokens[j].RevokedAt == nil {
				s.tokens[j].RevokedAt = &now
			}
		}
	}
	s.Events = append(s.Events, events...)
	return next, nil
}

// SetActive changes a user directly, without audit (test setup).
func (s *Store) SetActive(id string, active bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.users {
		if s.users[i].ID == id {
			s.users[i].IsActive = active
		}
	}
}

func (s *Tokens) Create(_ context.Context, t model.NewRefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = append(s.tokens, token{NewRefreshToken: t})
	return nil
}

func (s *Tokens) Rotate(_ context.Context, oldHash []byte, next model.NewRefreshToken, now time.Time) (model.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.tokens {
		t := &s.tokens[i]
		if !bytes.Equal(t.Hash, oldHash) {
			continue
		}
		ui, ok := (*Users)(s).find(func(u model.User) bool { return u.ID == t.UserID })
		if !ok || t.RevokedAt != nil || !now.Before(t.ExpiresAt) || !s.users[ui].IsActive {
			return model.User{}, model.ErrInvalidToken
		}
		t.RevokedAt = &now
		next.UserID = t.UserID
		s.tokens = append(s.tokens, token{NewRefreshToken: next})
		return s.users[ui], nil
	}
	return model.User{}, model.ErrInvalidToken
}

func (s *Tokens) Revoke(_ context.Context, hash []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.tokens {
		if bytes.Equal(s.tokens[i].Hash, hash) && s.tokens[i].RevokedAt == nil {
			s.tokens[i].RevokedAt = &now
		}
	}
	return nil
}

// ActiveTokens counts the tokens of a user that are neither revoked nor expired.
func (s *Store) ActiveTokens(userID string, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.tokens {
		if t.UserID == userID && t.RevokedAt == nil && now.Before(t.ExpiresAt) {
			n++
		}
	}
	return n
}
