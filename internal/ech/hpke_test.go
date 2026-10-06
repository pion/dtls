// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build go1.26

package ech

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"testing"

	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/stretchr/testify/require"
)

func TestHPKE(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	configs, err := ParseConfigList(configList(key.PublicKey().Bytes()))
	require.NoError(t, err)
	config, suite := configs[0], (CipherSuite{1, 1})
	for _, mandatory := range []bool{false, true} {
		var enc []byte
		var sender Sender
		if mandatory {
			config.Extensions = []extension.Raw{{Type: 0x8000}}
			configs, err = ParseConfigList(configListFor(config))
			require.NoError(t, err)
			config = configs[0]
			require.False(t, config.Usable())
			publicKey, keyErr := hpke.NewDHKEMPublicKey(key.PublicKey())
			require.NoError(t, keyErr)
			enc, sender, err = hpke.NewSender(publicKey, hpke.HKDFSHA256(), hpke.AES128GCM(), append([]byte("tls ech\x00"), config.Raw...))
		} else {
			enc, sender, err = NewSender(config, suite)
		}
		require.NoError(t, err)
		receiver, err := NewRecipient(config, suite, key.Bytes(), enc)
		require.NoError(t, err)
		inner := hello(t, nil, extension13.ECHClientHello{Type: extension13.ECHClientHelloInner},
			extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}})
		encoded, err := EncodeInnerClientHello(inner, config.MaxNameLength, -1)
		require.NoError(t, err)
		for range 2 { // Reuse the HPKE sequence state across ClientHellos.
			offer := extension13.ECHClientHello{KDF: 1, AEAD: 1, ConfigID: config.ConfigID, Enc: enc, Payload: make([]byte, len(encoded)+16)}
			aad, aadErr := OuterAAD(hello(t, nil, offer))
			require.NoError(t, aadErr)
			offer.Payload, err = sender.Seal(aad, encoded)
			require.NoError(t, err)
			wire := hello(t, nil, offer)
			receivedAAD, aadErr := OuterAAD(wire)
			require.NoError(t, aadErr)
			plaintext, openErr := receiver.Open(receivedAAD, offer.Payload)
			require.NoError(t, openErr)
			reconstructed, decodeErr := DecodeInnerClientHello(plaintext, wire)
			require.NoError(t, decodeErr)
			require.Equal(t, inner, reconstructed)
		}
		exported, err := sender.Export("test", 32)
		require.NoError(t, err)
		peer, err := receiver.Export("test", 32)
		require.NoError(t, err)
		require.Equal(t, exported, peer)
		ciphertext, err := sender.Seal([]byte("outer"), []byte("inner"))
		require.NoError(t, err)
		_, err = receiver.Open([]byte("tampered"), ciphertext)
		require.Error(t, err)
		_, _, err = NewSender(config, CipherSuite{1, 0xffff})
		require.Error(t, err)
		other, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		_, err = NewRecipient(config, suite, other.Bytes(), enc)
		require.Error(t, err)
	}
}
