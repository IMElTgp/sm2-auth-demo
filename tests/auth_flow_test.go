package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"task1-1/internal/api"
)

func TestHealthz(t *testing.T) {
	server := httptest.NewServer(api.NewMux())
	defer server.Close()

	resp, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: got %d want %d", resp.StatusCode, http.StatusOK)
	}
}
