package api

import (
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func TestGeneratedFixedWindowLimiterScenarios(t *testing.T) {
	for seed := int64(1); seed <= 100; seed++ {
		r := rand.New(rand.NewSource(seed))
		limiter := newFixedWindowLimiter()
		now := time.Unix(1000+seed, 0)
		limiter.now = func() time.Time { return now }

		key := "key-" + strconv.FormatInt(seed, 10)
		limit := 1 + r.Intn(20)
		window := time.Duration(1+r.Intn(60)) * time.Second
		requestsInWindow := limit + 1 + r.Intn(10)

		allowed := 0
		for i := 0; i < requestsInWindow; i++ {
			if limiter.Allow(key, limit, window) {
				allowed++
			}
		}
		if allowed != limit {
			t.Fatalf("seed %d allowed in window = %d, want %d", seed, allowed, limit)
		}

		now = now.Add(window)
		if !limiter.Allow(key, limit, window) {
			t.Fatalf("seed %d request after reset was rejected", seed)
		}
	}
}

func FuzzClientIP(f *testing.F) {
	f.Add("192.0.2.1:12345")
	f.Add("192.0.2.1")
	f.Add(" ")

	f.Fuzz(func(t *testing.T, remoteAddr string) {
		got := clientIP(remoteAddr)
		switch remoteAddr {
		case "192.0.2.1:12345":
			if got != "192.0.2.1" {
				t.Fatalf("clientIP(%q) = %q, want %q", remoteAddr, got, "192.0.2.1")
			}
		case "192.0.2.1":
			if got != "192.0.2.1" {
				t.Fatalf("clientIP(%q) = %q, want %q", remoteAddr, got, "192.0.2.1")
			}
		case " ":
			if got != "unknown" {
				t.Fatalf("clientIP(%q) = %q, want %q", remoteAddr, got, "unknown")
			}
		}
		if got == "" {
			t.Fatalf("clientIP(%q) returned empty string", remoteAddr)
		}
	})
}
