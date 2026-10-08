// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"bytes"
	"errors"

	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"golang.org/x/crypto/cryptobyte"
)

var errECH = errors.New("malformed ECH extension")

// ErrInvalidECHType identifies an unknown encrypted_client_hello variant.
var ErrInvalidECHType = errors.New("invalid ECH ClientHello type")

// ECHClientHelloType distinguishes the two encrypted_client_hello variants.
type ECHClientHelloType uint8

const (
	ECHClientHelloOuter ECHClientHelloType = 0
	ECHClientHelloInner ECHClientHelloType = 1
)

// ECHClientHello is the inner or outer RFC 9849 ClientHello extension.
//
// https://www.rfc-editor.org/rfc/rfc9849#section-5
type ECHClientHello struct {
	Type         ECHClientHelloType
	KDF, AEAD    uint16
	ConfigID     uint8
	Enc, Payload []byte
}

func (ECHClientHello) ExtensionType() extension.Type { return extension.TypeEncryptedClientHello }
func (e ECHClientHello) MarshalSize() int {
	if e.Type == ECHClientHelloInner {
		return 1
	}

	return 10 + len(e.Enc) + len(e.Payload)
}

func (e ECHClientHello) MarshalData() ([]byte, error) {
	if e.Type == ECHClientHelloInner {
		if e.KDF != 0 || e.AEAD != 0 || e.ConfigID != 0 || len(e.Enc) != 0 || len(e.Payload) != 0 {
			return nil, errECH
		}

		return []byte{1}, nil
	}
	if e.Type != ECHClientHelloOuter || len(e.Payload) == 0 || e.MarshalSize() > 65535 {
		return nil, errECH
	}
	var b cryptobyte.Builder
	b.AddUint8(0)
	b.AddUint16(e.KDF)
	b.AddUint16(e.AEAD)
	b.AddUint8(e.ConfigID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(e.Enc) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(e.Payload) })

	return b.Bytes()
}

func (e *ECHClientHello) UnmarshalData(data []byte) error {
	input := cryptobyte.String(data)
	var typ uint8
	if len(data) > 65535 || !input.ReadUint8(&typ) {
		return errECH
	}
	if typ == uint8(ECHClientHelloInner) {
		if !input.Empty() {
			return errECH
		}
		*e = ECHClientHello{Type: ECHClientHelloInner}

		return nil
	}
	if typ != uint8(ECHClientHelloOuter) {
		return ErrInvalidECHType
	}

	return e.unmarshalOuter(input)
}

func (e *ECHClientHello) unmarshalOuter(input cryptobyte.String) error {
	var value ECHClientHello
	var enc, payload cryptobyte.String
	if !input.ReadUint16(&value.KDF) || !input.ReadUint16(&value.AEAD) || !input.ReadUint8(&value.ConfigID) || !input.ReadUint16LengthPrefixed(&enc) || !input.ReadUint16LengthPrefixed(&payload) || len(payload) == 0 || !input.Empty() {
		return errECH
	}
	value.Enc = bytes.Clone(enc)
	value.Payload = bytes.Clone(payload)
	*e = value

	return nil
}

// ECHOuterExtensions references extensions carried by ClientHelloOuter.
type ECHOuterExtensions struct{ Types []extension.Type }

func (ECHOuterExtensions) ExtensionType() extension.Type { return extension.TypeECHOuterExtensions }
func (e ECHOuterExtensions) MarshalSize() int            { return 1 + 2*len(e.Types) }
func (e ECHOuterExtensions) MarshalData() ([]byte, error) {
	if len(e.Types) == 0 || len(e.Types) > 127 {
		return nil, errECH
	}
	seen := map[extension.Type]bool{}
	var b cryptobyte.Builder
	b.AddUint8(uint8(2 * len(e.Types))) //nolint:gosec // At most 127 two-byte types.
	for _, t := range e.Types {
		if seen[t] || t == extension.TypeEncryptedClientHello || t == extension.TypeECHOuterExtensions {
			return nil, errECH
		}
		seen[t] = true
		b.AddUint16(uint16(t))
	}

	return b.Bytes()
}

func (e *ECHOuterExtensions) UnmarshalData(data []byte) error {
	input := cryptobyte.String(data)
	var list cryptobyte.String
	if !input.ReadUint8LengthPrefixed(&list) || !input.Empty() || len(list) == 0 || len(list)%2 != 0 {
		return errECH
	}
	value := ECHOuterExtensions{}
	for !list.Empty() {
		var t uint16
		list.ReadUint16(&t)
		value.Types = append(value.Types, extension.Type(t))
	}
	if _, err := value.MarshalData(); err != nil {
		return err
	}
	*e = value

	return nil
}

// ECHHelloRetryRequest carries the acceptance confirmation.
type ECHHelloRetryRequest struct{ Confirmation [8]byte }

func (ECHHelloRetryRequest) ExtensionType() extension.Type { return extension.TypeEncryptedClientHello }
func (ECHHelloRetryRequest) MarshalSize() int              { return 8 }
func (e ECHHelloRetryRequest) MarshalData() ([]byte, error) {
	return bytes.Clone(e.Confirmation[:]), nil
}

func (e *ECHHelloRetryRequest) UnmarshalData(data []byte) error {
	if len(data) != 8 {
		return errECH
	}
	copy(e.Confirmation[:], data)

	return nil
}

// ECHRetryConfigs carries a framed ECHConfigList.
type ECHRetryConfigs struct{ ConfigList []byte }

func (ECHRetryConfigs) ExtensionType() extension.Type { return extension.TypeEncryptedClientHello }
func (e ECHRetryConfigs) MarshalSize() int            { return len(e.ConfigList) }
func (e ECHRetryConfigs) MarshalData() ([]byte, error) {
	var value ECHRetryConfigs
	if err := value.UnmarshalData(e.ConfigList); err != nil {
		return nil, err
	}

	return value.ConfigList, nil
}

func (e *ECHRetryConfigs) UnmarshalData(data []byte) error {
	input := cryptobyte.String(data)
	var list cryptobyte.String
	if len(data) > 65535 || !input.ReadUint16LengthPrefixed(&list) || !input.Empty() || len(list) < 4 {
		return errECH
	}
	for !list.Empty() {
		var version uint16
		var body cryptobyte.String
		if !list.ReadUint16(&version) || !list.ReadUint16LengthPrefixed(&body) {
			return errECH
		}
	}
	e.ConfigList = bytes.Clone(data)

	return nil
}
