package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"task1-1/internal/crypto"
	"task1-1/internal/protocol"
	"task1-1/internal/store"

	"github.com/emmansun/gmsm/sm3"
)

func NewMux() *http.ServeMux {
	defaultServer := NewServer(
		store.NewSQLiteUserStore(""),
		store.NewMemorySessionStore(),
		60*time.Second,
	)
	return NewMuxWithServer(defaultServer)
}

func NewMuxWithServer(server *Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/api/register", server.registerHandler)
	mux.HandleFunc("/api/auth/challenge", server.challengeHandler)
	mux.HandleFunc("/api/auth/verify", server.verifyHandler)
	return mux
}

type Server struct {
	userStore    store.UserStore
	sessionStore store.SessionStore
	sessionTTL   time.Duration
	limiter      *fixedWindowLimiter
	config       ServerConfig
}

type ServerConfig struct {
	SessionTTL      time.Duration
	RegisterLimit   int
	ChallengeLimit  int
	VerifyLimit     int
	RateLimitWindow time.Duration
}

func NewServer(userStore store.UserStore, sessionStore store.SessionStore, sessionTTL time.Duration) *Server {
	return NewServerWithConfig(userStore, sessionStore, ServerConfig{
		SessionTTL:      sessionTTL,
		RegisterLimit:   5,
		ChallengeLimit:  10,
		VerifyLimit:     10,
		RateLimitWindow: time.Minute,
	})
}

func NewServerWithConfig(userStore store.UserStore, sessionStore store.SessionStore, config ServerConfig) *Server {
	if config.SessionTTL <= 0 {
		config.SessionTTL = 60 * time.Second
	}
	if config.RegisterLimit <= 0 {
		config.RegisterLimit = 5
	}
	if config.ChallengeLimit <= 0 {
		config.ChallengeLimit = 10
	}
	if config.VerifyLimit <= 0 {
		config.VerifyLimit = 10
	}
	if config.RateLimitWindow <= 0 {
		config.RateLimitWindow = time.Minute
	}
	return &Server{
		userStore:    userStore,
		sessionStore: sessionStore,
		sessionTTL:   config.SessionTTL,
		limiter:      newFixedWindowLimiter(),
		config:       config,
	}
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, BaseResponse{OK: false, Error: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, BaseResponse{OK: false, Error: "method not allowed"})
		return
	}

	req, err := decodeRequest[RegisterRequest](r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, BaseResponse{OK: false, Error: "invalid request"})
		return
	}
	if req.Username == "" || req.Salt == "" || req.PublicKey == "" {
		writeJSON(w, http.StatusBadRequest, BaseResponse{OK: false, Error: "invalid request"})
		return
	}
	if !s.allowRequest(w, r, "register", "", s.config.RegisterLimit) {
		return
	}

	salt, err := base64.StdEncoding.DecodeString(req.Salt)
	if err != nil || len(salt) == 0 {
		writeJSON(w, http.StatusBadRequest, BaseResponse{OK: false, Error: "invalid salt"})
		return
	}
	publicKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(publicKey) == 0 {
		writeJSON(w, http.StatusBadRequest, BaseResponse{OK: false, Error: "invalid public_key"})
		return
	}
	if _, err := crypto.ParsePublicKey(publicKey); err != nil {
		writeJSON(w, http.StatusBadRequest, BaseResponse{OK: false, Error: "invalid public_key"})
		return
	}

	err = s.userStore.CreateUser(r.Context(), store.UserRecord{
		Username:  req.Username,
		Salt:      salt,
		PublicKey: publicKey,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		if errors.Is(err, store.ErrUserExists) {
			writeJSON(w, http.StatusOK, BaseResponse{OK: true, Message: "registered"})
			return
		}
		log.Printf("register failed: username=%s err=%v", req.Username, err)
		writeJSON(w, http.StatusInternalServerError, BaseResponse{OK: false, Error: "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, BaseResponse{OK: true, Message: "registered"})
}

func (s *Server) challengeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, BaseResponse{OK: false, Error: "method not allowed"})
		return
	}

	req, err := decodeRequest[ChallengeRequest](r.Body)
	if err != nil || req.Username == "" {
		writeJSON(w, http.StatusBadRequest, BaseResponse{OK: false, Error: "invalid request"})
		return
	}
	if !s.allowRequest(w, r, "challenge", req.Username, s.config.ChallengeLimit) {
		return
	}

	user, err := s.userStore.GetUser(r.Context(), req.Username)
	if err != nil {
		if errors.Is(err, store.ErrUserNotFound) {
			resp, fakeErr := fakeChallengeResponse()
			if fakeErr != nil {
				writeJSON(w, http.StatusInternalServerError, BaseResponse{OK: false, Error: "internal error"})
				return
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		log.Printf("challenge failed: username=%s err=%v", req.Username, err)
		writeJSON(w, http.StatusInternalServerError, BaseResponse{OK: false, Error: "internal error"})
		return
	}

	sessionID, err := randomSessionID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, BaseResponse{OK: false, Error: "internal error"})
		return
	}
	nonce, err := randomBytes(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, BaseResponse{OK: false, Error: "internal error"})
		return
	}
	expiresAt := time.Now().Add(s.sessionTTL)

	if err := s.sessionStore.Create(r.Context(), store.SessionRecord{
		SessionID: sessionID,
		Username:  req.Username,
		Nonce:     nonce,
		ExpiresAt: expiresAt,
	}); err != nil {
		log.Printf("challenge session store failed: username=%s err=%v", req.Username, err)
		writeJSON(w, http.StatusInternalServerError, BaseResponse{OK: false, Error: "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, ChallengeResponse{
		OK:        true,
		SessionID: sessionID,
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Salt:      base64.StdEncoding.EncodeToString(user.Salt),
	})
}

func (s *Server) verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, BaseResponse{OK: false, Error: "method not allowed"})
		return
	}

	req, err := decodeRequest[VerifyRequest](r.Body)
	if err != nil || req.Username == "" || req.SessionID == "" || req.Token == "" || req.Signature == "" {
		writeJSON(w, http.StatusBadRequest, BaseResponse{OK: false, Error: "invalid request"})
		return
	}
	if !s.allowRequest(w, r, "verify", req.Username, s.config.VerifyLimit) {
		return
	}

	session, err := s.sessionStore.Get(r.Context(), req.SessionID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, BaseResponse{OK: false, Error: "authentication failed"})
		return
	}

	if session.Username != req.Username {
		writeJSON(w, http.StatusUnauthorized, BaseResponse{OK: false, Error: "authentication failed"})
		return
	}

	user, err := s.userStore.GetUser(r.Context(), req.Username)
	if err != nil {
		log.Printf("verify user lookup failed: username=%s err=%v", req.Username, err)
		writeJSON(w, http.StatusUnauthorized, BaseResponse{OK: false, Error: "authentication failed"})
		return
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(req.Token)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, BaseResponse{OK: false, Error: "invalid token"})
		return
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, BaseResponse{OK: false, Error: "invalid signature"})
		return
	}

	expectedToken := protocol.AuthToken{
		Version:   tokenVersion,
		Username:  req.Username,
		SessionID: req.SessionID,
		Nonce:     session.Nonce,
	}
	expectedTokenBytes, err := expectedToken.CanonicalBytes()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, BaseResponse{OK: false, Error: "internal error"})
		return
	}
	if !bytes.Equal(tokenBytes, expectedTokenBytes) {
		writeJSON(w, http.StatusUnauthorized, BaseResponse{OK: false, Error: "authentication failed"})
		return
	}

	pub, err := crypto.ParsePublicKey(user.PublicKey)
	if err != nil {
		log.Printf("verify invalid user public key: username=%s err=%v", req.Username, err)
		writeJSON(w, http.StatusUnauthorized, BaseResponse{OK: false, Error: "authentication failed"})
		return
	}

	digest := sm3.Sum(tokenBytes)
	if err := crypto.VerifyToken(pub, digest[:], signatureBytes); err != nil {
		writeJSON(w, http.StatusUnauthorized, BaseResponse{OK: false, Error: "authentication failed"})
		return
	}
	if err := s.sessionStore.Consume(r.Context(), req.SessionID); err != nil {
		writeJSON(w, http.StatusUnauthorized, BaseResponse{OK: false, Error: "authentication failed"})
		return
	}

	writeJSON(w, http.StatusOK, BaseResponse{OK: true, Message: "authenticated"})
}

const tokenVersion = "AUTH-v1"

func decodeRequest[T any](body io.Reader) (T, error) {
	var req T
	decoder := json.NewDecoder(io.LimitReader(body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, err
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return req, errors.New("trailing data")
		}
		return req, err
	}
	return req, nil
}

func randomSessionID() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func fakeChallengeResponse() (ChallengeResponse, error) {
	sessionID, err := randomSessionID()
	if err != nil {
		return ChallengeResponse{}, err
	}
	nonce, err := randomBytes(32)
	if err != nil {
		return ChallengeResponse{}, err
	}
	salt, err := randomBytes(16)
	if err != nil {
		return ChallengeResponse{}, err
	}
	return ChallengeResponse{
		OK:        true,
		SessionID: sessionID,
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Salt:      base64.StdEncoding.EncodeToString(salt),
	}, nil
}

func (s *Server) allowRequest(w http.ResponseWriter, r *http.Request, action string, subject string, limit int) bool {
	key := action + "|" + clientIP(r.RemoteAddr) + "|" + subject
	if s.limiter.Allow(key, limit, s.config.RateLimitWindow) {
		return true
	}
	writeJSON(w, http.StatusTooManyRequests, BaseResponse{OK: false, Error: "too many requests"})
	return false
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
