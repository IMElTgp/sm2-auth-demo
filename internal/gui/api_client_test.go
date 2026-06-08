package gui

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"task1-1/internal/api"
	"task1-1/internal/store"
)

func TestAPIClientRegisterAndLogin(t *testing.T) {
	serverURL := newTestServerURL(t)
	client := NewAPIClient(serverURL)

	if err := client.Register("alice", []byte("correct-password")); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if err := client.Login("alice", []byte("correct-password")); err != nil {
		t.Fatalf("login failed: %v", err)
	}
}

func TestAPIClientLoginWrongPassword(t *testing.T) {
	serverURL := newTestServerURL(t)
	client := NewAPIClient(serverURL)

	if err := client.Register("alice", []byte("correct-password")); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if err := client.Login("alice", []byte("wrong-password")); err == nil {
		t.Fatalf("expected login failure for wrong password")
	}
}

func newTestServerURL(t *testing.T) string {
	t.Helper()

	userStore := store.NewSQLiteUserStore(filepath.Join(t.TempDir(), "users.db"))
	sessionStore := store.NewMemorySessionStore()
	server := api.NewServer(userStore, sessionStore, 60*time.Second)

	ts := httptest.NewServer(api.NewMuxWithServer(server))
	t.Cleanup(ts.Close)
	return ts.URL
}
