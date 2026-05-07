package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/emmansun/gmsm/sm2"
)

// PublicKeyBytes returns uncompressed public key bytes.
func PublicKeyBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.X == nil || pub.Y == nil || pub.Curve == nil {
		return nil, ErrInvalidPublicKey
	}
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y), nil
}

// ParsePublicKey parses uncompressed public key bytes.
func ParsePublicKey(publicKey []byte) (*ecdsa.PublicKey, error) {
	if len(publicKey) == 0 {
		return nil, ErrInvalidPublicKey
	}
	pub, err := sm2.NewPublicKey(publicKey)
	if err != nil {
		return nil, ErrInvalidPublicKey
	}
	return pub, nil
}

// SignToken signs a digest with the derived SM2 private key.
func SignToken(privateKey *sm2.PrivateKey, digest []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}
	if len(digest) == 0 {
		return nil, ErrInvalidDigestInput
	}
	return sm2.SignASN1(rand.Reader, privateKey, digest, nil)
}

// VerifyToken verifies a digest/signature pair using the user SM2 public key.
func VerifyToken(publicKey *ecdsa.PublicKey, digest []byte, signature []byte) error {
	if publicKey == nil {
		return ErrInvalidPublicKey
	}
	if len(digest) == 0 || len(signature) == 0 {
		return ErrInvalidInput
	}
	if !sm2.VerifyASN1(publicKey, digest, signature) {
		return ErrInvalidSignature
	}
	return nil
}
