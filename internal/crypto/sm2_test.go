package crypto

import (
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func TestSignAndVerifyToken(t *testing.T) {
	priv, err := DerivePrivateKey("alice", []byte("p@ssw0rd"), []byte("salt-001"))
	if err != nil {
		t.Fatalf("derive private key failed: %v", err)
	}

	payload := []byte("AUTH-v1|alice|sid-123|nonce")
	digest := sm3.Sum(payload)

	sig, err := SignToken(priv, digest[:])
	if err != nil {
		t.Fatalf("sign token failed: %v", err)
	}

	if err := VerifyToken(&priv.PublicKey, digest[:], sig); err != nil {
		t.Fatalf("verify should pass: %v", err)
	}
}

func TestVerifyTokenFailsWithWrongDigest(t *testing.T) {
	priv, err := DerivePrivateKey("alice", []byte("p@ssw0rd"), []byte("salt-001"))
	if err != nil {
		t.Fatalf("derive private key failed: %v", err)
	}

	digest := sm3.Sum([]byte("token-a"))
	sig, err := SignToken(priv, digest[:])
	if err != nil {
		t.Fatalf("sign token failed: %v", err)
	}

	wrongDigest := sm3.Sum([]byte("token-b"))
	if err := VerifyToken(&priv.PublicKey, wrongDigest[:], sig); err == nil {
		t.Fatalf("verify should fail for wrong digest")
	}
}

func TestVerifyTokenFailsWithWrongPublicKey(t *testing.T) {
	privA, err := DerivePrivateKey("alice", []byte("p@ssw0rd"), []byte("salt-001"))
	if err != nil {
		t.Fatalf("derive private key A failed: %v", err)
	}
	privB, err := DerivePrivateKey("bob", []byte("p@ssw0rd"), []byte("salt-002"))
	if err != nil {
		t.Fatalf("derive private key B failed: %v", err)
	}

	digest := sm3.Sum([]byte("token-a"))
	sig, err := SignToken(privA, digest[:])
	if err != nil {
		t.Fatalf("sign token failed: %v", err)
	}

	if err := VerifyToken(&privB.PublicKey, digest[:], sig); err == nil {
		t.Fatalf("verify should fail for wrong public key")
	}
}
