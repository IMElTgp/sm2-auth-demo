package store

import (
	"context"
	"sync"
	"time"
)

type MemorySessionStore struct {
	mu   sync.RWMutex
	data map[string]SessionRecord
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{
		data: make(map[string]SessionRecord),
	}
}

func (s *MemorySessionStore) Create(ctx context.Context, session SessionRecord) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[session.SessionID] = session
	return nil
}

func (s *MemorySessionStore) Get(ctx context.Context, sessionID string) (SessionRecord, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.data[sessionID]
	if !ok {
		return SessionRecord{}, ErrSessionNotFound
	}
	if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		delete(s.data, sessionID)
		return SessionRecord{}, ErrSessionExpired
	}
	return session, nil
}

func (s *MemorySessionStore) Consume(ctx context.Context, sessionID string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.data[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		delete(s.data, sessionID)
		return ErrSessionExpired
	}
	delete(s.data, sessionID)
	return nil
}

func (s *MemorySessionStore) Delete(ctx context.Context, sessionID string) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, sessionID)
	return nil
}
