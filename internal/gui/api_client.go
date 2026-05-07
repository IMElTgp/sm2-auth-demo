package gui

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"task1-1/internal/api"
	localcrypto "task1-1/internal/crypto"
	"task1-1/internal/protocol"

	"github.com/emmansun/gmsm/sm3"
)

const authTokenVersion = "AUTH-v1"

type APIClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewAPIClient(baseURL string) *APIClient {
	return &APIClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *APIClient) Register(username string, password []byte) error {
	if username == "" || len(password) == 0 {
		return errors.New("username and password are required")
	}
	defer wipeBytes(password)

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	priv, err := localcrypto.DerivePrivateKey(username, password, salt)
	if err != nil {
		return fmt.Errorf("derive private key: %w", err)
	}
	pub, err := localcrypto.PublicKeyBytes(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}

	req := api.RegisterRequest{
		Username:  username,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	var resp api.BaseResponse
	status, err := c.postJSON("/api/register", req, &resp)
	if err != nil {
		return err
	}
	if status != http.StatusOK || !resp.OK {
		return responseError(status, resp.Error, "register failed")
	}
	return nil
}

func (c *APIClient) Login(username string, password []byte) error {
	if username == "" || len(password) == 0 {
		return errors.New("username and password are required")
	}
	defer wipeBytes(password)

	var challenge api.ChallengeResponse
	status, err := c.postJSON("/api/auth/challenge", api.ChallengeRequest{Username: username}, &challenge)
	if err != nil {
		return err
	}
	if status != http.StatusOK || !challenge.OK {
		return responseError(status, challenge.Error, "challenge failed")
	}

	salt, err := base64.StdEncoding.DecodeString(challenge.Salt)
	if err != nil {
		return fmt.Errorf("decode challenge salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		return fmt.Errorf("decode challenge nonce: %w", err)
	}

	priv, err := localcrypto.DerivePrivateKey(username, password, salt)
	if err != nil {
		return fmt.Errorf("derive private key: %w", err)
	}

	token := protocol.AuthToken{
		Version:   authTokenVersion,
		Username:  username,
		SessionID: challenge.SessionID,
		Nonce:     nonce,
	}
	tokenBytes, err := token.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("build token: %w", err)
	}
	digest := sm3.Sum(tokenBytes)
	signature, err := localcrypto.SignToken(priv, digest[:])
	if err != nil {
		return fmt.Errorf("sign token: %w", err)
	}

	verifyReq := api.VerifyRequest{
		Username:  username,
		SessionID: challenge.SessionID,
		Token:     base64.StdEncoding.EncodeToString(tokenBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
	var verifyResp api.BaseResponse
	status, err = c.postJSON("/api/auth/verify", verifyReq, &verifyResp)
	if err != nil {
		return err
	}
	if status != http.StatusOK || !verifyResp.OK {
		return responseError(status, verifyResp.Error, "authentication failed")
	}
	return nil
}

func (c *APIClient) postJSON(path string, req any, resp any) (int, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return 0, fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL() + path
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}
	if len(respBytes) > 0 && resp != nil {
		if err := json.Unmarshal(respBytes, resp); err != nil {
			return httpResp.StatusCode, fmt.Errorf("decode response: %w", err)
		}
	}
	return httpResp.StatusCode, nil
}

func (c *APIClient) baseURL() string {
	base := strings.TrimSpace(c.BaseURL)
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	return strings.TrimRight(base, "/")
}

func responseError(status int, msg string, fallback string) error {
	if msg == "" {
		msg = fallback
	}
	return fmt.Errorf("%s (http %d)", msg, status)
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
