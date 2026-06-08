package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"task1-1/internal/api"
	localcrypto "task1-1/internal/crypto"
	"task1-1/internal/protocol"
	"task1-1/internal/store"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

func TestRegisterChallengeVerifyAndReplay(t *testing.T) {
	serverURL := newTestServer(t)

	username := "alice"
	password := []byte("correct-horse-battery-staple")
	salt := []byte("register-salt-001")

	priv, err := localcrypto.DerivePrivateKey(username, password, salt)
	if err != nil {
		t.Fatalf("derive private key failed: %v", err)
	}
	pub, err := localcrypto.PublicKeyBytes(&priv.PublicKey)
	if err != nil {
		t.Fatalf("serialize public key failed: %v", err)
	}

	registerReq := api.RegisterRequest{
		Username:  username,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	var registerResp api.BaseResponse
	status := postJSON(t, serverURL+"/api/register", registerReq, &registerResp)
	if status != http.StatusOK || !registerResp.OK {
		t.Fatalf("register failed: status=%d resp=%+v", status, registerResp)
	}

	var challengeResp api.ChallengeResponse
	status = postJSON(t, serverURL+"/api/auth/challenge", api.ChallengeRequest{Username: username}, &challengeResp)
	if status != http.StatusOK || !challengeResp.OK {
		t.Fatalf("challenge failed: status=%d resp=%+v", status, challengeResp)
	}
	if challengeResp.Salt != registerReq.Salt {
		t.Fatalf("challenge salt mismatch")
	}

	nonce, err := base64.StdEncoding.DecodeString(challengeResp.Nonce)
	if err != nil {
		t.Fatalf("decode nonce failed: %v", err)
	}
	token := protocol.AuthToken{
		Version:   "AUTH-v1",
		Username:  username,
		SessionID: challengeResp.SessionID,
		Nonce:     nonce,
	}
	tokenBytes, err := token.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical token failed: %v", err)
	}

	digest := sm3.Sum(tokenBytes)
	signature, err := localcrypto.SignToken(priv, digest[:])
	if err != nil {
		t.Fatalf("sign token failed: %v", err)
	}

	verifyReq := api.VerifyRequest{
		Username:  username,
		SessionID: challengeResp.SessionID,
		Token:     base64.StdEncoding.EncodeToString(tokenBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
	var verifyResp api.BaseResponse
	status = postJSON(t, serverURL+"/api/auth/verify", verifyReq, &verifyResp)
	if status != http.StatusOK || !verifyResp.OK {
		t.Fatalf("verify failed: status=%d resp=%+v", status, verifyResp)
	}

	var replayResp api.BaseResponse
	status = postJSON(t, serverURL+"/api/auth/verify", verifyReq, &replayResp)
	if status != http.StatusUnauthorized || replayResp.OK {
		t.Fatalf("replay should fail: status=%d resp=%+v", status, replayResp)
	}
}

func TestDuplicateRegisterAndWrongPassword(t *testing.T) {
	serverURL := newTestServer(t)

	username := "alice"
	password := []byte("good-password")
	salt := []byte("register-salt-002")

	priv, err := localcrypto.DerivePrivateKey(username, password, salt)
	if err != nil {
		t.Fatalf("derive private key failed: %v", err)
	}
	pub, err := localcrypto.PublicKeyBytes(&priv.PublicKey)
	if err != nil {
		t.Fatalf("serialize public key failed: %v", err)
	}
	registerReq := api.RegisterRequest{
		Username:  username,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}

	var registerResp1 api.BaseResponse
	status := postJSON(t, serverURL+"/api/register", registerReq, &registerResp1)
	if status != http.StatusOK || !registerResp1.OK {
		t.Fatalf("first register failed: status=%d resp=%+v", status, registerResp1)
	}

	var registerResp2 api.BaseResponse
	status = postJSON(t, serverURL+"/api/register", registerReq, &registerResp2)
	if status != http.StatusOK || !registerResp2.OK {
		t.Fatalf("duplicate register should not leak existence: status=%d resp=%+v", status, registerResp2)
	}

	var challengeResp api.ChallengeResponse
	status = postJSON(t, serverURL+"/api/auth/challenge", api.ChallengeRequest{Username: username}, &challengeResp)
	if status != http.StatusOK || !challengeResp.OK {
		t.Fatalf("challenge failed: status=%d resp=%+v", status, challengeResp)
	}

	saltFromServer, err := base64.StdEncoding.DecodeString(challengeResp.Salt)
	if err != nil {
		t.Fatalf("decode salt failed: %v", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(challengeResp.Nonce)
	if err != nil {
		t.Fatalf("decode nonce failed: %v", err)
	}

	wrongPriv, err := localcrypto.DerivePrivateKey(username, []byte("bad-password"), saltFromServer)
	if err != nil {
		t.Fatalf("derive wrong private key failed: %v", err)
	}

	token := protocol.AuthToken{
		Version:   "AUTH-v1",
		Username:  username,
		SessionID: challengeResp.SessionID,
		Nonce:     nonce,
	}
	tokenBytes, err := token.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical token failed: %v", err)
	}
	digest := sm3.Sum(tokenBytes)
	signature, err := localcrypto.SignToken(wrongPriv, digest[:])
	if err != nil {
		t.Fatalf("sign token with wrong password key failed: %v", err)
	}

	verifyReq := api.VerifyRequest{
		Username:  username,
		SessionID: challengeResp.SessionID,
		Token:     base64.StdEncoding.EncodeToString(tokenBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
	var verifyResp api.BaseResponse
	status = postJSON(t, serverURL+"/api/auth/verify", verifyReq, &verifyResp)
	if status != http.StatusUnauthorized || verifyResp.OK {
		t.Fatalf("wrong password verify should fail: status=%d resp=%+v", status, verifyResp)
	}
}

func TestTamperedNonceInTokenFails(t *testing.T) {
	serverURL := newTestServer(t)

	username := "alice"
	password := []byte("good-password")
	salt := []byte("register-salt-003")

	priv, err := localcrypto.DerivePrivateKey(username, password, salt)
	if err != nil {
		t.Fatalf("derive private key failed: %v", err)
	}
	pub, err := localcrypto.PublicKeyBytes(&priv.PublicKey)
	if err != nil {
		t.Fatalf("serialize public key failed: %v", err)
	}
	registerReq := api.RegisterRequest{
		Username:  username,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	var registerResp api.BaseResponse
	status := postJSON(t, serverURL+"/api/register", registerReq, &registerResp)
	if status != http.StatusOK || !registerResp.OK {
		t.Fatalf("register failed: status=%d resp=%+v", status, registerResp)
	}

	var challengeResp api.ChallengeResponse
	status = postJSON(t, serverURL+"/api/auth/challenge", api.ChallengeRequest{Username: username}, &challengeResp)
	if status != http.StatusOK || !challengeResp.OK {
		t.Fatalf("challenge failed: status=%d resp=%+v", status, challengeResp)
	}
	nonce, err := base64.StdEncoding.DecodeString(challengeResp.Nonce)
	if err != nil {
		t.Fatalf("decode nonce failed: %v", err)
	}
	// Tamper nonce to verify token mismatch path.
	nonce[0] ^= 0xFF

	token := protocol.AuthToken{
		Version:   "AUTH-v1",
		Username:  username,
		SessionID: challengeResp.SessionID,
		Nonce:     nonce,
	}
	tokenBytes, err := token.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical token failed: %v", err)
	}
	digest := sm3.Sum(tokenBytes)
	signature, err := localcrypto.SignToken(priv, digest[:])
	if err != nil {
		t.Fatalf("sign token failed: %v", err)
	}

	verifyReq := api.VerifyRequest{
		Username:  username,
		SessionID: challengeResp.SessionID,
		Token:     base64.StdEncoding.EncodeToString(tokenBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
	var verifyResp api.BaseResponse
	status = postJSON(t, serverURL+"/api/auth/verify", verifyReq, &verifyResp)
	if status != http.StatusUnauthorized || verifyResp.OK {
		t.Fatalf("tampered nonce should fail: status=%d resp=%+v", status, verifyResp)
	}
}

func TestExpiredChallengeFails(t *testing.T) {
	serverURL := newTestServerWithTTL(t, 20*time.Millisecond)

	username := "alice"
	password := []byte("good-password")
	salt := []byte("register-salt-004")

	priv, err := localcrypto.DerivePrivateKey(username, password, salt)
	if err != nil {
		t.Fatalf("derive private key failed: %v", err)
	}
	pub, err := localcrypto.PublicKeyBytes(&priv.PublicKey)
	if err != nil {
		t.Fatalf("serialize public key failed: %v", err)
	}
	registerReq := api.RegisterRequest{
		Username:  username,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	var registerResp api.BaseResponse
	status := postJSON(t, serverURL+"/api/register", registerReq, &registerResp)
	if status != http.StatusOK || !registerResp.OK {
		t.Fatalf("register failed: status=%d resp=%+v", status, registerResp)
	}

	var challengeResp api.ChallengeResponse
	status = postJSON(t, serverURL+"/api/auth/challenge", api.ChallengeRequest{Username: username}, &challengeResp)
	if status != http.StatusOK || !challengeResp.OK {
		t.Fatalf("challenge failed: status=%d resp=%+v", status, challengeResp)
	}
	nonce, err := base64.StdEncoding.DecodeString(challengeResp.Nonce)
	if err != nil {
		t.Fatalf("decode nonce failed: %v", err)
	}
	time.Sleep(120 * time.Millisecond)

	token := protocol.AuthToken{
		Version:   "AUTH-v1",
		Username:  username,
		SessionID: challengeResp.SessionID,
		Nonce:     nonce,
	}
	tokenBytes, err := token.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical token failed: %v", err)
	}
	digest := sm3.Sum(tokenBytes)
	signature, err := localcrypto.SignToken(priv, digest[:])
	if err != nil {
		t.Fatalf("sign token failed: %v", err)
	}

	verifyReq := api.VerifyRequest{
		Username:  username,
		SessionID: challengeResp.SessionID,
		Token:     base64.StdEncoding.EncodeToString(tokenBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
	var verifyResp api.BaseResponse
	status = postJSON(t, serverURL+"/api/auth/verify", verifyReq, &verifyResp)
	if status != http.StatusUnauthorized || verifyResp.OK {
		t.Fatalf("expired challenge should fail: status=%d resp=%+v", status, verifyResp)
	}
}

func TestFailedVerifyDoesNotConsumeChallenge(t *testing.T) {
	serverURL := newTestServer(t)

	username := "alice"
	password := []byte("good-password")
	salt := []byte("register-salt-005")

	priv, err := localcrypto.DerivePrivateKey(username, password, salt)
	if err != nil {
		t.Fatalf("derive private key failed: %v", err)
	}
	pub, err := localcrypto.PublicKeyBytes(&priv.PublicKey)
	if err != nil {
		t.Fatalf("serialize public key failed: %v", err)
	}
	registerReq := api.RegisterRequest{
		Username:  username,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	var registerResp api.BaseResponse
	status := postJSON(t, serverURL+"/api/register", registerReq, &registerResp)
	if status != http.StatusOK || !registerResp.OK {
		t.Fatalf("register failed: status=%d resp=%+v", status, registerResp)
	}

	var challengeResp api.ChallengeResponse
	status = postJSON(t, serverURL+"/api/auth/challenge", api.ChallengeRequest{Username: username}, &challengeResp)
	if status != http.StatusOK || !challengeResp.OK {
		t.Fatalf("challenge failed: status=%d resp=%+v", status, challengeResp)
	}

	nonce, err := base64.StdEncoding.DecodeString(challengeResp.Nonce)
	if err != nil {
		t.Fatalf("decode nonce failed: %v", err)
	}
	wrongPriv, err := localcrypto.DerivePrivateKey(username, []byte("bad-password"), salt)
	if err != nil {
		t.Fatalf("derive wrong private key failed: %v", err)
	}

	badVerifyReq := buildVerifyRequest(t, username, challengeResp.SessionID, nonce, wrongPriv)
	var badVerifyResp api.BaseResponse
	status = postJSON(t, serverURL+"/api/auth/verify", badVerifyReq, &badVerifyResp)
	if status != http.StatusUnauthorized || badVerifyResp.OK {
		t.Fatalf("wrong password verify should fail: status=%d resp=%+v", status, badVerifyResp)
	}

	goodVerifyReq := buildVerifyRequest(t, username, challengeResp.SessionID, nonce, priv)
	var goodVerifyResp api.BaseResponse
	status = postJSON(t, serverURL+"/api/auth/verify", goodVerifyReq, &goodVerifyResp)
	if status != http.StatusOK || !goodVerifyResp.OK {
		t.Fatalf("valid verify after failed attempt should succeed: status=%d resp=%+v", status, goodVerifyResp)
	}
}

func TestConcurrentVerifyOnlyOneSucceeds(t *testing.T) {
	serverURL := newTestServerWithConfig(t, api.ServerConfig{
		SessionTTL:      60 * time.Second,
		RegisterLimit:   20,
		ChallengeLimit:  20,
		VerifyLimit:     128,
		RateLimitWindow: time.Minute,
	})

	username := "alice"
	password := []byte("good-password")
	salt := []byte("register-salt-006")

	priv, err := localcrypto.DerivePrivateKey(username, password, salt)
	if err != nil {
		t.Fatalf("derive private key failed: %v", err)
	}
	pub, err := localcrypto.PublicKeyBytes(&priv.PublicKey)
	if err != nil {
		t.Fatalf("serialize public key failed: %v", err)
	}
	registerReq := api.RegisterRequest{
		Username:  username,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	var registerResp api.BaseResponse
	status := postJSON(t, serverURL+"/api/register", registerReq, &registerResp)
	if status != http.StatusOK || !registerResp.OK {
		t.Fatalf("register failed: status=%d resp=%+v", status, registerResp)
	}

	var challengeResp api.ChallengeResponse
	status = postJSON(t, serverURL+"/api/auth/challenge", api.ChallengeRequest{Username: username}, &challengeResp)
	if status != http.StatusOK || !challengeResp.OK {
		t.Fatalf("challenge failed: status=%d resp=%+v", status, challengeResp)
	}
	nonce, err := base64.StdEncoding.DecodeString(challengeResp.Nonce)
	if err != nil {
		t.Fatalf("decode nonce failed: %v", err)
	}
	verifyReq := buildVerifyRequest(t, username, challengeResp.SessionID, nonce, priv)

	var successCount int32
	var unauthorizedCount int32
	var otherCount int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var verifyResp api.BaseResponse
			verifyStatus, verifyErr := postJSONStatus(serverURL+"/api/auth/verify", verifyReq, &verifyResp)
			if verifyErr != nil {
				atomic.AddInt32(&otherCount, 1)
				return
			}
			switch verifyStatus {
			case http.StatusOK:
				atomic.AddInt32(&successCount, 1)
			case http.StatusUnauthorized:
				atomic.AddInt32(&unauthorizedCount, 1)
			default:
				atomic.AddInt32(&otherCount, 1)
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly one successful verify, got %d", successCount)
	}
	if unauthorizedCount != 31 {
		t.Fatalf("expected remaining requests to be unauthorized, got %d unauthorized", unauthorizedCount)
	}
	if otherCount != 0 {
		t.Fatalf("unexpected non-auth results: %d", otherCount)
	}
}

func TestChallengeForMissingUserDoesNotEnumerate(t *testing.T) {
	serverURL := newTestServer(t)

	var challengeResp api.ChallengeResponse
	status := postJSON(t, serverURL+"/api/auth/challenge", api.ChallengeRequest{Username: "missing-user"}, &challengeResp)
	if status != http.StatusOK || !challengeResp.OK {
		t.Fatalf("missing user challenge should be indistinguishable from success: status=%d resp=%+v", status, challengeResp)
	}
	if challengeResp.SessionID == "" || challengeResp.Nonce == "" || challengeResp.Salt == "" {
		t.Fatalf("missing user challenge should still return challenge-shaped payload: %+v", challengeResp)
	}
}

func TestVerifyRateLimit(t *testing.T) {
	serverURL := newTestServerWithConfig(t, api.ServerConfig{
		SessionTTL:      60 * time.Second,
		RegisterLimit:   20,
		ChallengeLimit:  20,
		VerifyLimit:     3,
		RateLimitWindow: time.Minute,
	})

	username := "alice"
	password := []byte("good-password")
	salt := []byte("register-salt-007")

	priv, err := localcrypto.DerivePrivateKey(username, password, salt)
	if err != nil {
		t.Fatalf("derive private key failed: %v", err)
	}
	pub, err := localcrypto.PublicKeyBytes(&priv.PublicKey)
	if err != nil {
		t.Fatalf("serialize public key failed: %v", err)
	}
	registerReq := api.RegisterRequest{
		Username:  username,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	var registerResp api.BaseResponse
	status := postJSON(t, serverURL+"/api/register", registerReq, &registerResp)
	if status != http.StatusOK || !registerResp.OK {
		t.Fatalf("register failed: status=%d resp=%+v", status, registerResp)
	}

	var challengeResp api.ChallengeResponse
	status = postJSON(t, serverURL+"/api/auth/challenge", api.ChallengeRequest{Username: username}, &challengeResp)
	if status != http.StatusOK || !challengeResp.OK {
		t.Fatalf("challenge failed: status=%d resp=%+v", status, challengeResp)
	}
	nonce, err := base64.StdEncoding.DecodeString(challengeResp.Nonce)
	if err != nil {
		t.Fatalf("decode nonce failed: %v", err)
	}
	wrongPriv, err := localcrypto.DerivePrivateKey(username, []byte("bad-password"), salt)
	if err != nil {
		t.Fatalf("derive wrong private key failed: %v", err)
	}
	verifyReq := buildVerifyRequest(t, username, challengeResp.SessionID, nonce, wrongPriv)

	for i := 0; i < 3; i++ {
		var verifyResp api.BaseResponse
		status = postJSON(t, serverURL+"/api/auth/verify", verifyReq, &verifyResp)
		if status != http.StatusUnauthorized || verifyResp.OK {
			t.Fatalf("attempt %d should fail with unauthorized before rate limit: status=%d resp=%+v", i+1, status, verifyResp)
		}
	}

	var rateLimitedResp api.BaseResponse
	status = postJSON(t, serverURL+"/api/auth/verify", verifyReq, &rateLimitedResp)
	if status != http.StatusTooManyRequests || rateLimitedResp.OK {
		t.Fatalf("verify should be rate limited: status=%d resp=%+v", status, rateLimitedResp)
	}
}

func TestTrailingJSONRejected(t *testing.T) {
	serverURL := newTestServer(t)

	rawBody := `{"username":"alice"}{"ignored":true}`
	httpResp, err := http.Post(serverURL+"/api/auth/challenge", "application/json", bytes.NewBufferString(rawBody))
	if err != nil {
		t.Fatalf("http post failed: %v", err)
	}
	defer httpResp.Body.Close()

	var resp api.BaseResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if httpResp.StatusCode != http.StatusBadRequest || resp.OK {
		t.Fatalf("trailing json should be rejected: status=%d resp=%+v", httpResp.StatusCode, resp)
	}
}

func newTestServer(t *testing.T) string {
	t.Helper()
	return newTestServerWithTTL(t, 60*time.Second)
}

func newTestServerWithTTL(t *testing.T, ttl time.Duration) string {
	t.Helper()
	return newTestServerWithConfig(t, api.ServerConfig{
		SessionTTL:      ttl,
		RegisterLimit:   20,
		ChallengeLimit:  20,
		VerifyLimit:     20,
		RateLimitWindow: time.Minute,
	})
}

func newTestServerWithConfig(t *testing.T, config api.ServerConfig) string {
	t.Helper()

	userStore := store.NewSQLiteUserStore(filepath.Join(t.TempDir(), "users.db"))
	sessionStore := store.NewMemorySessionStore()
	app := api.NewServerWithConfig(userStore, sessionStore, config)

	ts := httptest.NewServer(api.NewMuxWithServer(app))
	t.Cleanup(ts.Close)
	return ts.URL
}

func postJSON(t *testing.T, url string, req any, resp any) int {
	t.Helper()

	status, err := postJSONStatus(url, req, resp)
	if err != nil {
		t.Fatalf("post json failed: %v", err)
	}
	return status
}

func postJSONStatus(url string, req any, resp any) (int, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return 0, err
	}

	httpResp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	defer httpResp.Body.Close()

	if resp != nil {
		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return 0, err
		}
		if len(body) > 0 {
			if err := json.Unmarshal(body, resp); err != nil {
				return 0, err
			}
		}
	}
	return httpResp.StatusCode, nil
}

func buildVerifyRequest(t *testing.T, username string, sessionID string, nonce []byte, priv *sm2.PrivateKey) api.VerifyRequest {
	t.Helper()

	token := protocol.AuthToken{
		Version:   "AUTH-v1",
		Username:  username,
		SessionID: sessionID,
		Nonce:     append([]byte(nil), nonce...),
	}
	tokenBytes, err := token.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical token failed: %v", err)
	}
	digest := sm3.Sum(tokenBytes)
	signature, err := localcrypto.SignToken(priv, digest[:])
	if err != nil {
		t.Fatalf("sign token failed: %v", err)
	}
	return api.VerifyRequest{
		Username:  username,
		SessionID: sessionID,
		Token:     base64.StdEncoding.EncodeToString(tokenBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
}
