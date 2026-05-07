package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteUserStore struct {
	dsn     string
	db      *sql.DB
	initErr error
	once    sync.Once
}

func NewSQLiteUserStore(dsn string) *SQLiteUserStore {
	return &SQLiteUserStore{dsn: dsn}
}

func (s *SQLiteUserStore) CreateUser(ctx context.Context, user UserRecord) error {
	if user.Username == "" || len(user.Salt) == 0 || len(user.PublicKey) == 0 {
		return errors.New("invalid user record")
	}
	if err := s.ensureInitialized(); err != nil {
		return err
	}

	createdAt := user.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO users (username, salt, public_key, created_at) VALUES (?, ?, ?, ?)`,
		user.Username,
		user.Salt,
		user.PublicKey,
		createdAt.UnixNano(),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrUserExists
		}
		return err
	}
	return nil
}

func (s *SQLiteUserStore) GetUser(ctx context.Context, username string) (UserRecord, error) {
	if username == "" {
		return UserRecord{}, errors.New("invalid username")
	}
	if err := s.ensureInitialized(); err != nil {
		return UserRecord{}, err
	}

	var (
		user           UserRecord
		createdAtNanos int64
	)
	err := s.db.QueryRowContext(
		ctx,
		`SELECT username, salt, public_key, created_at FROM users WHERE username = ?`,
		username,
	).Scan(&user.Username, &user.Salt, &user.PublicKey, &createdAtNanos)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UserRecord{}, ErrUserNotFound
		}
		return UserRecord{}, err
	}
	user.CreatedAt = time.Unix(0, createdAtNanos).UTC()
	return user, nil
}

func (s *SQLiteUserStore) ensureInitialized() error {
	s.once.Do(func() {
		dsn := s.dsn
		if dsn == "" {
			dsn = "file:auth.db?mode=rwc&_pragma=busy_timeout(5000)"
		}

		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			s.initErr = err
			return
		}

		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(0)

		_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS users (
	username   TEXT PRIMARY KEY,
	salt       BLOB NOT NULL,
	public_key BLOB NOT NULL,
	created_at INTEGER NOT NULL
);`)
		if err != nil {
			_ = db.Close()
			s.initErr = err
			return
		}

		s.db = db
	})
	return s.initErr
}
