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
	// 使用稳定的 length-prefixed 编码，避免依赖 JSON 键顺序或字符串分隔符约定。
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
	// 统一使用大端长度前缀，便于跨语言实现相同的 token 编码规则。
	if err := binary.Write(buf, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := buf.Write(data)
	return err
}
