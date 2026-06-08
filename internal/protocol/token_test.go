package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"testing"
)

func TestGeneratedAuthTokenCanonicalBytes(t *testing.T) {
	for seed := int64(1); seed <= 100; seed++ {
		token := generateToken(seed)
		got, err := token.CanonicalBytes()
		if err != nil {
			t.Fatalf("seed %d CanonicalBytes() error = %v", seed, err)
		}
		fields, err := readCanonicalFields(got)
		if err != nil {
			t.Fatalf("seed %d readCanonicalFields() error = %v", seed, err)
		}
		want := [][]byte{
			[]byte(token.Version),
			[]byte(token.Username),
			[]byte(token.SessionID),
			token.Nonce,
		}
		for i := range want {
			if !bytes.Equal(fields[i], want[i]) {
				t.Fatalf("seed %d field %d = %x, want %x", seed, i, fields[i], want[i])
			}
		}
	}
}

func FuzzAuthTokenCanonicalBytes(f *testing.F) {
	f.Add("AUTH-v1", "alice", "sid-1", []byte{1, 2, 3})
	f.Add("", "alice", "sid-1", []byte{1})
	f.Add("AUTH-v1", "", "sid-1", []byte{1})
	f.Add("AUTH-v1", "alice", "", []byte{1})
	f.Add("AUTH-v1", "alice", "sid-1", []byte{})

	f.Fuzz(func(t *testing.T, version string, username string, sessionID string, nonce []byte) {
		token := AuthToken{
			Version:   version,
			Username:  username,
			SessionID: sessionID,
			Nonce:     nonce,
		}
		got, err := token.CanonicalBytes()
		if version == "" || username == "" || sessionID == "" || len(nonce) == 0 {
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("CanonicalBytes() error = %v, want %v", err, ErrInvalidToken)
			}
			return
		}
		if err != nil {
			t.Fatalf("CanonicalBytes() error = %v", err)
		}
		fields, err := readCanonicalFields(got)
		if err != nil {
			t.Fatalf("readCanonicalFields() error = %v", err)
		}
		if string(fields[0]) != version || string(fields[1]) != username || string(fields[2]) != sessionID || !bytes.Equal(fields[3], nonce) {
			t.Fatalf("decoded fields do not match token: %#v", token)
		}
	})
}

func generateToken(seed int64) AuthToken {
	r := rand.New(rand.NewSource(seed))
	return AuthToken{
		Version:   generatedASCII(r, "version", 20),
		Username:  generatedASCII(r, "user", 32),
		SessionID: generatedASCII(r, "session", 32),
		Nonce:     generatedBytes(r, 1+r.Intn(64)),
	}
}

func readCanonicalFields(data []byte) ([][]byte, error) {
	reader := bytes.NewReader(data)
	fields := make([][]byte, 0, 4)
	for i := 0; i < 4; i++ {
		var size uint32
		if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
			return nil, err
		}
		field := make([]byte, size)
		if _, err := io.ReadFull(reader, field); err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	if reader.Len() != 0 {
		return nil, errors.New("trailing canonical data")
	}
	return fields, nil
}

func generatedASCII(r *rand.Rand, prefix string, maxSuffix int) string {
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
		buf[i] = byte(r.Intn(256))
	}
	return buf
}
