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
	Inner             []byte
	Recipient         Recipient
	ConfigID          uint8
	Suite             CipherSuite
	InitialInner      []byte
	HelloRetryRequest []byte
	retryOuter        []byte
}

// ProcessRetry reuses the receiving context for ClientHello2. Exact duplicates
// return the cached plaintext without advancing the HPKE sequence number.
// https://www.rfc-editor.org/rfc/rfc9849#section-7.1.1
func (c *ServerContext) ProcessRetry(outer []byte) ([]byte, error) {
	if c.retryOuter != nil {
		if !bytes.Equal(c.retryOuter, outer) {
			return nil, serverError(alert.IllegalParameter, ErrInvalid)
		}

		return bytes.Clone(c.Inner), nil
	}
	_, exts, err := splitHello(outer, false)
	if err != nil {
		return nil, serverError(alert.DecodeError, err)
	}
	i := extensionIndex(exts, extension.TypeEncryptedClientHello)
	if i < 0 {
		return nil, serverError(alert.MissingExtension, ErrInvalid)
	}
	var offer extension13.ECHClientHello
	if err = offer.UnmarshalData(exts[i].Data); err != nil {
		return nil, serverError(alert.DecodeError, err)
	}
	if (offer.Type == extension13.ECHClientHelloInner) != (c.Recipient == nil) {
		return nil, serverError(alert.DecodeError, ErrInvalid)
	}
	inner, err := c.decryptRetry(outer, offer)
	if err != nil {
		return nil, err
	}
	c.retryOuter = bytes.Clone(outer)
	c.Inner = inner

	return bytes.Clone(inner), nil
}

func (c *ServerContext) decryptRetry(outer []byte, offer extension13.ECHClientHello) ([]byte, error) {
	if c.Recipient == nil {
		context, err := ProcessClientHello(outer, nil)

		return context.Inner, err
	}
	if offer.ConfigID != c.ConfigID || (CipherSuite{KDFID: offer.KDF, AEADID: offer.AEAD}) != c.Suite || len(offer.Enc) != 0 {
		return nil, serverError(alert.IllegalParameter, ErrInvalid)
	}
	aad, err := OuterAAD(outer)
	if err != nil {
		return nil, serverError(alert.IllegalParameter, err)
	}
	encoded, err := c.Recipient.Open(aad, offer.Payload)
	if err != nil {
		return nil, serverError(alert.DecryptError, err)
	}
	inner, err := DecodeInnerClientHello(encoded, outer)
	if err != nil {
		return nil, serverError(alert.IllegalParameter, err)
	}

	return inner, nil
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

	return confirmation(hashFunc, inner, nil, hello, "ech accept confirmation")
}

// RetryConfirmation computes HRR confirmation with its ECH extension zeroed.
func RetryConfirmation(hashFunc func() hash.Hash, inner, zeroedHRR []byte) ([]byte, error) {
	if hashFunc == nil || len(inner) < 34 || len(inner) > 0xffffff {
		return nil, ErrInvalid
	}

	return confirmation(hashFunc, inner, retryPrefix(hashFunc, inner, nil), zeroedHRR, "hrr ech accept confirmation")
}

// Confirmation includes the synthetic message_hash and HRR after a retry.
func (c *ServerContext) Confirmation(hashFunc func() hash.Hash, serverHello []byte) ([]byte, error) {
	return acceptanceConfirmation(hashFunc, c.Inner, c.InitialInner, c.HelloRetryRequest, serverHello)
}

// acceptanceConfirmation uses the selected inner history, including HRR when present.
func acceptanceConfirmation(hashFunc func() hash.Hash, inner, initialInner, hrr, serverHello []byte) ([]byte, error) {
	if len(hrr) == 0 {
		return AcceptanceConfirmation(hashFunc, inner, serverHello)
	}
	if hashFunc == nil || len(initialInner) < 34 || len(initialInner) > 0xffffff || len(hrr) > 0xffffff || len(serverHello) < 34 {
		return nil, ErrInvalid
	}
	hello := bytes.Clone(serverHello)
	clear(hello[26:34])

	return confirmation(hashFunc, inner, retryPrefix(hashFunc, initialInner, hrr), hello, "ech accept confirmation")
}

func retryPrefix(hashFunc func() hash.Hash, inner, hrr []byte) []byte {
	digest := hashFunc()
	digest.Write(canonicalHello(1, inner))
	prefix := canonicalHello(254, digest.Sum(nil))
	if hrr != nil {
		prefix = append(prefix, canonicalHello(2, hrr)...)
	}

	return prefix
}

func canonicalHello(typ uint8, body []byte) []byte {
	var b cryptobyte.Builder
	b.AddUint8(typ)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(body) })

	return b.BytesOrPanic()
}

func confirmation(hashFunc func() hash.Hash, inner, prefix, hello []byte, label string) ([]byte, error) {
	if len(inner) < 34 || hashFunc == nil {
		return nil, ErrInvalid
	}
	var transcript cryptobyte.Builder
	transcript.AddBytes(prefix)
	if label != "hrr ech accept confirmation" {
		transcript.AddUint8(1) // ClientHello.
		transcript.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(inner) })
	}
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

	return keyschedule.HkdfExpandLabel(hashFunc, secret, label, digest.Sum(nil), 8)
}
