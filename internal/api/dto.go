package api

type RegisterRequest struct {
	Username  string `json:"username"`
	Salt      string `json:"salt"`
	PublicKey string `json:"public_key"`
}

type ChallengeRequest struct {
	Username string `json:"username"`
}

type VerifyRequest struct {
	Username  string `json:"username"`
	SessionID string `json:"session_id"`
	Token     string `json:"token"`
	Signature string `json:"signature"`
}

type BaseResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

type ChallengeResponse struct {
	OK        bool   `json:"ok"`
	SessionID string `json:"session_id,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	Salt      string `json:"salt,omitempty"`
	Error     string `json:"error,omitempty"`
}
