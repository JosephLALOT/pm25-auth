// Package audit appends admin writes to public.audit_event, the audit trail
// shared with pm25-api. The database user pm25_auth may only INSERT there
// (no SELECT, so no RETURNING either).
package audit

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgconn"
)

type Event struct {
	UserID     string // the admin who made the change ("sub" of the token)
	Action     string // user.role_change, user.status_change
	TargetType string // user
	TargetID   string
	Details    map[string]any
}

// Execer is a pool or a transaction: events are written in the transaction
// of the change they describe.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func Write(ctx context.Context, db Execer, e Event) error {
	var details []byte
	if e.Details != nil {
		var err error
		if details, err = json.Marshal(e.Details); err != nil {
			return err
		}
	}
	_, err := db.Exec(ctx,
		`INSERT INTO public.audit_event (user_id, action, target_type, target_id, details)
		 VALUES (NULLIF($1::text, '')::uuid, $2, NULLIF($3::text, ''), NULLIF($4::text, ''), $5::jsonb)`,
		e.UserID, e.Action, e.TargetType, e.TargetID, details)
	return err
}
