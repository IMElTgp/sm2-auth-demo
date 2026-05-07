package crypto

import (
	"encoding/binary"
	"errors"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
)

const (
	kdfDomainLabel = "GM-PWD-AUTH-KDF-v1"
	maxKDFRetries  = 1024
)

var (
	ErrInvalidInput       = errors.New("invalid input")
	ErrDerivePrivateKey   = errors.New("failed to derive sm2 private key")
	ErrInvalidSignature   = errors.New("invalid signature")
	ErrInvalidPublicKey   = errors.New("invalid public key")
	ErrInvalidPrivateKey  = errors.New("invalid private key")
	ErrInvalidDigestInput = errors.New("invalid digest input")
)

// DerivePrivateKey deterministically derives an SM2 private key from
// username/password/salt and handles invalid key boundaries by retrying
// with a counter.
func DerivePrivateKey(username string, password []byte, salt []byte) (*sm2.PrivateKey, error) {
	if username == "" || len(password) == 0 || len(salt) == 0 {
		return nil, ErrInvalidInput
	}

	for counter := uint32(0); counter < maxKDFRetries; counter++ {
		material := buildKDFMaterial(username, password, salt, counter)
		sum := sm3.Sum(material)

		priv, err := sm2.NewPrivateKey(sum[:])
		if err == nil {
			return priv, nil
		}
	}

	return nil, ErrDerivePrivateKey
}

func buildKDFMaterial(username string, password []byte, salt []byte, counter uint32) []byte {
	buf := make([]byte, 0, len(kdfDomainLabel)+4+len(username)+4+len(password)+4+len(salt)+4)
	buf = appendWithLength(buf, []byte(kdfDomainLabel))
	buf = appendWithLength(buf, []byte(username))
	buf = appendWithLength(buf, password)
	buf = appendWithLength(buf, salt)

	counterBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(counterBytes, counter)
	buf = append(buf, counterBytes...)
	return buf
}

func appendWithLength(dst []byte, src []byte) []byte {
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(src)))
	dst = append(dst, lenBytes...)
	dst = append(dst, src...)
	return dst
}
