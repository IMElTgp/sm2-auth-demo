package crypto

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestGeneratedDerivePrivateKeyIsDeterministic(t *testing.T) {
	for seed := int64(1); seed <= 50; seed++ {
		username, password, salt := generatedCredentials(seed)
		first, err := DerivePrivateKey(username, password, salt)
		if err != nil {
			t.Fatalf("seed %d DerivePrivateKey() first error = %v", seed, err)
		}
		second, err := DerivePrivateKey(username, password, salt)
		if err != nil {
			t.Fatalf("seed %d DerivePrivateKey() second error = %v", seed, err)
		}

		firstPub, err := PublicKeyBytes(&first.PublicKey)
		if err != nil {
			t.Fatalf("seed %d PublicKeyBytes(first) error = %v", seed, err)
		}
		secondPub, err := PublicKeyBytes(&second.PublicKey)
		if err != nil {
			t.Fatalf("seed %d PublicKeyBytes(second) error = %v", seed, err)
		}
		if !bytes.Equal(firstPub, secondPub) {
			t.Fatalf("seed %d derived public keys differ: %x != %x", seed, firstPub, secondPub)
		}
	}
}

func FuzzDerivePrivateKeyInputValidation(f *testing.F) {
	f.Add("alice", []byte("password"), []byte("salt"))
	f.Add("", []byte("password"), []byte("salt"))
	f.Add("alice", []byte{}, []byte("salt"))
	f.Add("alice", []byte("password"), []byte{})

	f.Fuzz(func(t *testing.T, username string, password []byte, salt []byte) {
		_, err := DerivePrivateKey(username, password, salt)
		if username == "" || len(password) == 0 || len(salt) == 0 {
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("DerivePrivateKey() error = %v, want %v", err, ErrInvalidInput)
			}
			return
		}
		if err != nil {
			t.Fatalf("DerivePrivateKey() error = %v", err)
		}
	})
}

func TestGeneratedSignAndVerifyTokenWithParsedPublicKey(t *testing.T) {
	for seed := int64(1); seed <= 30; seed++ {
		username, password, salt := generatedCredentials(seed)
		payload := generatedPayload(seed + 1000)
		privateKey, err := DerivePrivateKey(username, password, salt)
		if err != nil {
			t.Fatalf("seed %d DerivePrivateKey() error = %v", seed, err)
		}

		digest := sm3.Sum(payload)
		signature, err := SignToken(privateKey, digest[:])
		if err != nil {
			t.Fatalf("seed %d SignToken() error = %v", seed, err)
		}

		publicKeyBytes, err := PublicKeyBytes(&privateKey.PublicKey)
		if err != nil {
			t.Fatalf("seed %d PublicKeyBytes() error = %v", seed, err)
		}
		publicKey, err := ParsePublicKey(publicKeyBytes)
		if err != nil {
			t.Fatalf("seed %d ParsePublicKey() error = %v", seed, err)
		}
		if err := VerifyToken(publicKey, digest[:], signature); err != nil {
			t.Fatalf("seed %d VerifyToken() error = %v", seed, err)
		}

		wrongDigest := sm3.Sum(generatedPayload(seed + 2000))
		if err := VerifyToken(publicKey, wrongDigest[:], signature); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("seed %d VerifyToken() error = %v, want %v", seed, err, ErrInvalidSignature)
		}
	}
}

func generatedCredentials(seed int64) (string, []byte, []byte) {
	r := rand.New(rand.NewSource(seed))
	return generatedText(r, "user", 24), generatedBytes(r, 8+r.Intn(32)), generatedBytes(r, 8+r.Intn(24))
}

func generatedPayload(seed int64) []byte {
	r := rand.New(rand.NewSource(seed))
	return generatedBytes(r, 1+r.Intn(128))
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
