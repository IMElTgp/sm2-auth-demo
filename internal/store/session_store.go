package store

import (
	"context"
	"time"
)

type SessionRecord struct {
	SessionID string
	Username  string
	Nonce     []byte
	ExpiresAt time.Time
}

type SessionStore interface {
	Create(ctx context.Context, session SessionRecord) error
	Get(ctx context.Context, sessionID string) (SessionRecord, error)
	Consume(ctx context.Context, sessionID string) error
	Delete(ctx context.Context, sessionID string) error
}
