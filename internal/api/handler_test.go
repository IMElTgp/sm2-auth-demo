package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authcrypto "task1-1/internal/crypto"
	"task1-1/internal/protocol"
	"task1-1/internal/store"

	"github.com/emmansun/gmsm/sm3"
)

func TestGeneratedAuthScenarios(t *testing.T) {
	mutations := []string{"success", "replay", "wrong_username", "tampered_token"}
	for seed := int64(1); seed <= 10; seed++ {
		for _, mutation := range mutations {
			scenario := generateAuthScenario(seed, mutation)
			t.Run(scenario.name, func(t *testing.T) {
				runAuthScenario(t, scenario)
			})
		}
	}
}

func TestGeneratedMissingUserChallenges(t *testing.T) {
	for seed := int64(1); seed <= 10; seed++ {
		r := rand.New(rand.NewSource(seed))
		username := generatedText(r, "missing", 18)
		server := NewServerWithConfig(newTestUserStore(), store.NewMemorySessionStore(), ServerConfig{
			SessionTTL:      time.Minute,
			ChallengeLimit:  10,
			RateLimitWindow: time.Minute,
		})
		resp := doJSON[ChallengeResponse](t, NewMuxWithServer(server), http.MethodPost, "/api/auth/challenge", ChallengeRequest{Username: username})
		if resp.Code != http.StatusOK || !resp.Body.OK || resp.Body.SessionID == "" || resp.Body.Nonce == "" || resp.Body.Salt == "" {
			t.Fatalf("seed %d challenge missing user response = code %d body %+v", seed, resp.Code, resp.Body)
		}
	}
}

func TestGeneratedRegisterRateLimit(t *testing.T) {
	server := NewServerWithConfig(newTestUserStore(), store.NewMemorySessionStore(), ServerConfig{
		SessionTTL:      time.Minute,
		RegisterLimit:   1,
		RateLimitWindow: time.Minute,
	})
	mux := NewMuxWithServer(server)

	r := rand.New(rand.NewSource(99))
	req := RegisterRequest{
		Username:  generatedText(r, "rate", 14),
		Salt:      generatedText(r, "bad-salt", 8),
		PublicKey: generatedText(r, "bad-key", 8),
	}
	first := doJSON[BaseResponse](t, mux, http.MethodPost, "/api/register", req)
	if first.Code != http.StatusBadRequest {
		t.Fatalf("first register code = %d, want %d", first.Code, http.StatusBadRequest)
	}
	second := doJSON[BaseResponse](t, mux, http.MethodPost, "/api/register", req)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second register code = %d, want %d", second.Code, http.StatusTooManyRequests)
	}
}

type authScenario struct {
	name     string
	username string
	password []byte
	salt     []byte
	mutation string
}

func generateAuthScenario(seed int64, mutation string) authScenario {
	r := rand.New(rand.NewSource(seed))
	return authScenario{
		name:     generatedText(r, mutation, 20),
		username: generatedText(r, "user", 16),
		password: generatedBytes(r, 12+r.Intn(18)),
		salt:     generatedBytes(r, 8+r.Intn(16)),
		mutation: mutation,
	}
}

func runAuthScenario(t *testing.T, scenario authScenario) {
	t.Helper()
	userStore := newTestUserStore()
	sessionStore := store.NewMemorySessionStore()
	server := NewServerWithConfig(userStore, sessionStore, ServerConfig{
		SessionTTL:      time.Minute,
		RegisterLimit:   20,
		ChallengeLimit:  20,
		VerifyLimit:     20,
		RateLimitWindow: time.Minute,
	})
	mux := NewMuxWithServer(server)

	privateKey, err := authcrypto.DerivePrivateKey(scenario.username, scenario.password, scenario.salt)
	if err != nil {
		t.Fatalf("DerivePrivateKey() error = %v", err)
	}
	publicKeyBytes, err := authcrypto.PublicKeyBytes(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("PublicKeyBytes() error = %v", err)
	}

	registerResp := doJSON[BaseResponse](t, mux, http.MethodPost, "/api/register", RegisterRequest{
		Username:  scenario.username,
		Salt:      base64.StdEncoding.EncodeToString(scenario.salt),
		PublicKey: base64.StdEncoding.EncodeToString(publicKeyBytes),
	})
	if registerResp.Code != http.StatusOK || !registerResp.Body.OK {
		t.Fatalf("register response = code %d body %+v", registerResp.Code, registerResp.Body)
	}

	challengeResp := doJSON[ChallengeResponse](t, mux, http.MethodPost, "/api/auth/challenge", ChallengeRequest{Username: scenario.username})
	if challengeResp.Code != http.StatusOK || !challengeResp.Body.OK {
		t.Fatalf("challenge response = code %d body %+v", challengeResp.Code, challengeResp.Body)
	}
	nonce, err := base64.StdEncoding.DecodeString(challengeResp.Body.Nonce)
	if err != nil {
		t.Fatalf("DecodeString(nonce) error = %v", err)
	}
	tokenBytes, err := protocol.AuthToken{
		Version:   tokenVersion,
		Username:  scenario.username,
		SessionID: challengeResp.Body.SessionID,
		Nonce:     nonce,
	}.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes() error = %v", err)
	}
	digest := sm3.Sum(tokenBytes)
	signature, err := authcrypto.SignToken(privateKey, digest[:])
	if err != nil {
		t.Fatalf("SignToken() error = %v", err)
	}

	verifyReq := VerifyRequest{
		Username:  scenario.username,
		SessionID: challengeResp.Body.SessionID,
		Token:     base64.StdEncoding.EncodeToString(tokenBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
	wantCode := http.StatusOK
	switch scenario.mutation {
	case "success":
	case "replay":
	case "wrong_username":
		verifyReq.Username = scenario.username + "-other"
		wantCode = http.StatusUnauthorized
	case "tampered_token":
		tokenBytes[len(tokenBytes)-1] ^= 0xff
		verifyReq.Token = base64.StdEncoding.EncodeToString(tokenBytes)
		wantCode = http.StatusUnauthorized
	default:
		t.Fatalf("unknown mutation %q", scenario.mutation)
	}

	verifyResp := doJSON[BaseResponse](t, mux, http.MethodPost, "/api/auth/verify", verifyReq)
	if verifyResp.Code != wantCode {
		t.Fatalf("%s verify code = %d, want %d body %+v", scenario.mutation, verifyResp.Code, wantCode, verifyResp.Body)
	}
	if scenario.mutation == "success" && !verifyResp.Body.OK {
		t.Fatalf("success verify body = %+v", verifyResp.Body)
	}
	if scenario.mutation != "replay" {
		return
	}

	replayResp := doJSON[BaseResponse](t, mux, http.MethodPost, "/api/auth/verify", verifyReq)
	if replayResp.Code != http.StatusUnauthorized {
		t.Fatalf("replay verify code = %d, want %d", replayResp.Code, http.StatusUnauthorized)
	}
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
		buf[i] = byte(1 + r.Intn(255))
	}
	return buf
}

type jsonResponse[T any] struct {
	Code int
	Body T
}

func doJSON[T any](t *testing.T, handler http.Handler, method string, path string, body any) jsonResponse[T] {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	var decoded T
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("Unmarshal(%q) error = %v", rec.Body.String(), err)
	}
	return jsonResponse[T]{Code: rec.Code, Body: decoded}
}

type testUserStore struct {
	users map[string]store.UserRecord
}

func newTestUserStore() *testUserStore {
	return &testUserStore{users: make(map[string]store.UserRecord)}
}

func (s *testUserStore) CreateUser(ctx context.Context, user store.UserRecord) error {
	_ = ctx
	if _, ok := s.users[user.Username]; ok {
		return store.ErrUserExists
	}
	s.users[user.Username] = user
	return nil
}

func (s *testUserStore) GetUser(ctx context.Context, username string) (store.UserRecord, error) {
	_ = ctx
	user, ok := s.users[username]
	if !ok {
		return store.UserRecord{}, store.ErrUserNotFound
	}
	if user.Username == "" {
		return store.UserRecord{}, errors.New("invalid test user")
	}
	return user, nil
}
