package store

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"
)

func TestGeneratedSQLiteUserStoreCreateAndGetUser(t *testing.T) {
	ctx := context.Background()
	store := NewSQLiteUserStore("file:" + t.TempDir() + "/users.db?mode=rwc")

	for seed := int64(1); seed <= 30; seed++ {
		user := generatedUser(seed)
		if err := store.CreateUser(ctx, user); err != nil {
			t.Fatalf("seed %d CreateUser() error = %v", seed, err)
		}
		got, err := store.GetUser(ctx, user.Username)
		if err != nil {
			t.Fatalf("seed %d GetUser() error = %v", seed, err)
		}
		if got.Username != user.Username || string(got.Salt) != string(user.Salt) || string(got.PublicKey) != string(user.PublicKey) || !got.CreatedAt.Equal(user.CreatedAt) {
			t.Fatalf("seed %d GetUser() = %+v, want %+v", seed, got, user)
		}
	}
}

func TestGeneratedSQLiteUserStoreDuplicateAndMissingUser(t *testing.T) {
	ctx := context.Background()
	store := NewSQLiteUserStore("file:" + t.TempDir() + "/users.db?mode=rwc")
	user := generatedUser(999)

	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if err := store.CreateUser(ctx, user); !errors.Is(err, ErrUserExists) {
		t.Fatalf("CreateUser() duplicate error = %v, want %v", err, ErrUserExists)
	}
	missing := generatedUser(1000).Username
	if _, err := store.GetUser(ctx, missing); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("GetUser() missing error = %v, want %v", err, ErrUserNotFound)
	}
}

func generatedUser(seed int64) UserRecord {
	r := rand.New(rand.NewSource(seed))
	return UserRecord{
		Username:  generatedUserText(r, "user", 24),
		Salt:      generatedUserBytes(r, 1+r.Intn(32)),
		PublicKey: generatedUserBytes(r, 1+r.Intn(96)),
		CreatedAt: time.Unix(1000+seed, int64(r.Intn(1_000_000))).UTC(),
	}
}

func generatedUserText(r *rand.Rand, prefix string, maxSuffix int) string {
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

func generatedUserBytes(r *rand.Rand, size int) []byte {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(1 + r.Intn(255))
	}
	return buf
}
