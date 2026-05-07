package api

import (
	"net"
	"strings"
	"sync"
	"time"
)

type fixedWindowLimiter struct {
	mu      sync.Mutex
	entries map[string]limitEntry
	now     func() time.Time
}

type limitEntry struct {
	windowStart time.Time
	count       int
}

func newFixedWindowLimiter() *fixedWindowLimiter {
	return &fixedWindowLimiter{
		entries: make(map[string]limitEntry),
		now:     time.Now,
	}
}

func (l *fixedWindowLimiter) Allow(key string, limit int, window time.Duration) bool {
	if limit <= 0 {
		return true
	}

	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok || now.Sub(entry.windowStart) >= window {
		l.entries[key] = limitEntry{
			windowStart: now,
			count:       1,
		}
		l.cleanup(now, window)
		return true
	}

	if entry.count >= limit {
		return false
	}

	entry.count++
	l.entries[key] = entry
	return true
}

func (l *fixedWindowLimiter) cleanup(now time.Time, window time.Duration) {
	if len(l.entries) < 1024 {
		return
	}
	for key, entry := range l.entries {
		if now.Sub(entry.windowStart) >= window {
			delete(l.entries, key)
		}
	}
}

func clientIP(remoteAddr string) string {
	addr := strings.TrimSpace(remoteAddr)
	if addr == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return addr
	}
	return host
}
