// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ech

import (
	"bytes"
	"errors"
	"fmt"
	"hash"

	"github.com/pion/dtls/v4/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"golang.org/x/crypto/cryptobyte"
)

// Key associates a serialized ECHConfig with its HPKE private key.
type Key struct {
	Config, PrivateKey []byte
	SendAsRetry        bool
}

// ServerContext retains the accepted logical hello and receiving HPKE context.
// Its zero value means ECH was not accepted.
type ServerContext struct {
	Inner     []byte
	Recipient Recipient
	ConfigID  uint8
	Suite     CipherSuite
}

// ProcessClientHello follows crypto/tls trial decryption. A zero context means
// ECH was not accepted.
// https://www.rfc-editor.org/rfc/rfc9849#section-7.1
func ProcessClientHello(outer []byte, keys []Key) (ServerContext, error) {
	_, exts, err := splitHello(outer, false)
	if err != nil {
		return ServerContext{}, serverError(alert.DecodeError, err)
	}
	i := extensionIndex(exts, extension.TypeEncryptedClientHello)
	if i < 0 {
		return ServerContext{}, nil
	}
	var offer extension13.ECHClientHello
	if err = offer.UnmarshalData(exts[i].Data); err != nil {
		description := alert.DecodeError
		if errors.Is(err, extension13.ErrInvalidECHType) {
			description = alert.IllegalParameter
		}

		return ServerContext{}, serverError(description, err)
	}
	if offer.Type == extension13.ECHClientHelloInner {
		return acceptForwardedInner(outer, exts)
	}
	if len(keys) == 0 {
		return ServerContext{}, nil
	}
	if !Available() {
		return ServerContext{}, serverError(alert.InternalError, ErrToolchain)
	}
	aad, err := OuterAAD(outer)
	if err != nil {
		return ServerContext{}, serverError(alert.IllegalParameter, err)
	}

	return decryptClientHello(outer, aad, offer, keys)
}

// A forwarded logical inner must already have its outer references expanded.
func acceptForwardedInner(inner []byte, exts []extension.Raw) (ServerContext, error) {
	if extensionIndex(exts, extension.TypeECHOuterExtensions) >= 0 || !validInnerExtensions(exts) {
		return ServerContext{}, serverError(alert.IllegalParameter, ErrInvalid)
	}

	return ServerContext{Inner: bytes.Clone(inner)}, nil
}

func decryptClientHello(outer, aad []byte, offer extension13.ECHClientHello, keys []Key) (ServerContext, error) {
	suite := CipherSuite{KDFID: offer.KDF, AEADID: offer.AEAD}
	for _, key := range keys {
		skip, config, err := ParseConfig(key.Config)
		if err != nil {
			return ServerContext{}, serverError(alert.InternalError, ErrInvalid)
		}
		if skip {
			continue
		}
		recipient, err := NewRecipient(config, suite, key.PrivateKey, offer.Enc)
		if err != nil {
			var fatal *alert.Alert
			if errors.As(err, &fatal) {
				return ServerContext{}, err
			}

			continue
		}
		encoded, err := recipient.Open(aad, offer.Payload)
		if err != nil {
			continue
		}
		inner, err := DecodeInnerClientHello(encoded, outer)
		if err != nil {
			return ServerContext{}, serverError(alert.IllegalParameter, err)
		}

		return ServerContext{Inner: inner, Recipient: recipient, ConfigID: offer.ConfigID, Suite: suite}, nil
	}

	return ServerContext{}, nil
}

func serverError(description alert.Description, err error) error {
	return fmt.Errorf("ECH: %w: %w", err, &alert.Alert{Level: alert.Fatal, Description: description})
}

// AcceptanceConfirmation computes the normal ServerHello confirmation, with
// the final eight random bytes zeroed. Inputs are headerless DTLS bodies;
// https://www.rfc-editor.org/rfc/rfc9849#section-7.2
// https://www.rfc-editor.org/rfc/rfc9147#section-5.9
func AcceptanceConfirmation(hashFunc func() hash.Hash, inner, serverHello []byte) ([]byte, error) {
	if len(inner) < 34 || len(serverHello) < 34 || hashFunc == nil {
		return nil, ErrInvalid
	}
	hello := bytes.Clone(serverHello)
	clear(hello[26:34])
	var transcript cryptobyte.Builder
	transcript.AddUint8(1) // ClientHello.
	transcript.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(inner) })
	transcript.AddUint8(2) // ServerHello.
	transcript.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(hello) })
	encoded, err := transcript.Bytes()
	if err != nil {
		return nil, err
	}
	digest := hashFunc()
	_, _ = digest.Write(encoded)
	secret, err := keyschedule.HkdfExtract(hashFunc, nil, inner[2:34])
	if err != nil {
		return nil, err
	}

	return keyschedule.HkdfExpandLabel(hashFunc, secret, "ech accept confirmation", digest.Sum(nil), 8)
}
