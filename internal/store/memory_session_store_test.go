package store

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"
)

func TestGeneratedMemorySessionStoreScenarios(t *testing.T) {
	ctx := context.Background()
	for seed := int64(1); seed <= 100; seed++ {
		t.Run(generatedSessionName(seed), func(t *testing.T) {
			r := rand.New(rand.NewSource(seed))
			store := NewMemorySessionStore()
			session := generatedSession(r, time.Now().Add(time.Duration(1+r.Intn(120))*time.Second))

			if err := store.Create(ctx, session); err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			got, err := store.Get(ctx, session.SessionID)
			if err != nil {
				t.Fatalf("Get() error = %v", err)
			}
			if got.SessionID != session.SessionID || got.Username != session.Username || string(got.Nonce) != string(session.Nonce) {
				t.Fatalf("Get() = %+v, want %+v", got, session)
			}
			if err := store.Consume(ctx, session.SessionID); err != nil {
				t.Fatalf("Consume() error = %v", err)
			}
			if _, err := store.Get(ctx, session.SessionID); !errors.Is(err, ErrSessionNotFound) {
				t.Fatalf("Get() after Consume error = %v, want %v", err, ErrSessionNotFound)
			}
		})
	}
}

func TestGeneratedMemorySessionStoreExpiresSessions(t *testing.T) {
	ctx := context.Background()
	for seed := int64(1); seed <= 50; seed++ {
		r := rand.New(rand.NewSource(seed))
		store := NewMemorySessionStore()
		session := generatedSession(r, time.Now().Add(-time.Duration(1+r.Intn(120))*time.Second))

		if err := store.Create(ctx, session); err != nil {
			t.Fatalf("seed %d Create() error = %v", seed, err)
		}
		if _, err := store.Get(ctx, session.SessionID); !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("seed %d Get() error = %v, want %v", seed, err, ErrSessionExpired)
		}
		if _, err := store.Get(ctx, session.SessionID); !errors.Is(err, ErrSessionNotFound) {
			t.Fatalf("seed %d Get() after expiry cleanup error = %v, want %v", seed, err, ErrSessionNotFound)
		}
	}
}

func generatedSession(r *rand.Rand, expiresAt time.Time) SessionRecord {
	return SessionRecord{
		SessionID: generatedText(r, "session", 24),
		Username:  generatedText(r, "user", 18),
		Nonce:     generatedBytes(r, 1+r.Intn(64)),
		ExpiresAt: expiresAt,
	}
}

func generatedSessionName(seed int64) string {
	r := rand.New(rand.NewSource(seed))
	return generatedText(r, "seed", 12)
}

func generatedText(r *rand.Rand, prefix string, maxSuffix int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	size := 1 + r.Intn(maxSuffix)
	buf := make([]byte, 0, len(prefix)+1+size)
	buf = append(buf, prefix...)
	buf = append(buf, '-')
	for i := 0; i < size; i++ {
		buf = append(buf, alphabet[r.Intn(len(alphabet))])
	}
	return string(buf)
}

func generatedBytes(r *rand.Rand, size int) []byte {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(r.Intn(256))
	}
	return buf
}
