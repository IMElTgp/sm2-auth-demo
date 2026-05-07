package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
)

var ErrInvalidToken = errors.New("invalid token")

type AuthToken struct {
	Version   string
	Username  string
	SessionID string
	Nonce     []byte
}

func (t AuthToken) Validate() error {
	if t.Version == "" || t.Username == "" || t.SessionID == "" || len(t.Nonce) == 0 {
		return ErrInvalidToken
	}
	return nil
}

func (t AuthToken) CanonicalBytes() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(nil)
	if err := writeField(buf, []byte(t.Version)); err != nil {
		return nil, err
	}
	if err := writeField(buf, []byte(t.Username)); err != nil {
		return nil, err
	}
	if err := writeField(buf, []byte(t.SessionID)); err != nil {
		return nil, err
	}
	if err := writeField(buf, t.Nonce); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeField(buf *bytes.Buffer, data []byte) error {
	if err := binary.Write(buf, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := buf.Write(data)
	return err
}
