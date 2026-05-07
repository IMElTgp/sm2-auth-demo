package store

import (
	"context"
	"time"
)

type UserRecord struct {
	Username  string
	Salt      []byte
	PublicKey []byte
	CreatedAt time.Time
}

type UserStore interface {
	CreateUser(ctx context.Context, user UserRecord) error
	GetUser(ctx context.Context, username string) (UserRecord, error)
}
