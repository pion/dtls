// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPSKBinder(t *testing.T) {
	psk := decodeRegressionHex(t, "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5")
	transcriptHash := sha256.Sum256([]byte("ClientHello...ServerHello"))
	// Generated with nodejs / OpenSSL HMAC.
	for _, test := range []struct {
		external bool
		expected string
	}{
		{true, "7cee0522a65fbd2aaa968a63232d9064c8326c88901a0c9f471234752602bc3d"},
		{false, "2466a17c9daf7301cc1ff73ad89cd21f372a59175ccccd8db0b7cea83e07b53c"},
	} {
		binder, err := PSKBinderVerifyData(sha256.New, psk, transcriptHash[:], test.external)
		require.NoError(t, err)
		assert.Equal(t, decodeRegressionHex(t, test.expected), binder)
		require.NoError(t, VerifyPSKBinder(sha256.New, psk, transcriptHash[:], binder, test.external))
		binder[0] ^= 1
		assert.ErrorIs(t, VerifyPSKBinder(sha256.New, psk, transcriptHash[:], binder, test.external), dtlserrors.ErrVerifyDataMismatch)
	}
}

func TestFinalizeClientHelloWithPSKs(t *testing.T) {
	base := &handshake.MessageClientHello{
		Version: protocol.Version1_2, CipherSuiteIDs: []uint16{0x1301},
		CompressionMethods: []*protocol.CompressionMethod{{ID: 0}},
	}
	psks := []PSK{
		{Identity: []byte("one"), Secret: []byte("secret1"), Hash: crypto.SHA256, External: true},
		{Identity: []byte("two"), Secret: []byte("secret2"), Hash: crypto.SHA384, External: true},
		{Identity: []byte("three"), Secret: []byte("secret3"), Hash: crypto.SHA256, External: true},
	}
	cfg := &dtlsconfig.HandshakeConfig{ClientHelloMessageHook: func(h handshake.MessageClientHello) handshake.Message {
		h.SessionID = []byte("hooked")

		return &h
	}}
	transcript := NewTranscript()
	hello, snapshot, err := FinalizeClientHelloWithPSKs(base, cfg, psks, transcript)
	require.NoError(t, err)
	assert.Empty(t, base.Extensions)
	assert.Empty(t, transcript.Bytes())
	assert.Equal(t, []byte("hooked"), hello.SessionID)
	offer, ok := hello.Extensions[len(hello.Extensions)-1].(*extension13.OfferedPSKs)
	require.True(t, ok)
	raw := rawHandshakeMessage13(t, 42, hello)
	prefix, err := ClientHelloBinderPrefix(raw)
	require.NoError(t, err)
	assert.Equal(t, raw[:4], prefix[:4])
	const bindersSize = 2 + 2*(1+sha256.Size) + 1 + sha512.Size384
	assert.Equal(t, raw[handshake.HeaderLength:len(raw)-bindersSize], prefix[4:])
	for i, psk := range psks {
		hasher := psk.Hash.New()
		_, err = hasher.Write(prefix)
		require.NoError(t, err)
		assert.NoError(t, VerifyPSKBinder(psk.Hash.New, psk.Secret, hasher.Sum(nil), offer.Binders[i], true))
	}
	encoded, err := offer.MarshalData()
	require.NoError(t, err)
	saved, ok := snapshot.Extension(extension.TypePreSharedKey)
	require.True(t, ok)
	assert.Equal(t, encoded, saved.Data)

	cfg.ClientHelloMessageHook = func(h handshake.MessageClientHello) handshake.Message {
		h.Extensions = h.Extensions[:len(h.Extensions)-1]

		return &h
	}
	_, _, err = FinalizeClientHelloWithPSKs(base, cfg, psks, transcript)
	assert.ErrorIs(t, err, dtlserrors.ErrPreSharedKeyFormat)
}
