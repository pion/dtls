// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build go1.26

package ech

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"testing"

	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
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

func TestClientHelloConstruction(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	list := configList(key.PublicKey().Bytes())
	for _, serverName := range []string{"secret.example", ""} {
		t.Run(serverName, func(t *testing.T) {
			exts := []extension.Value{extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3, protocol.Version1_2}}}
			if serverName != "" {
				exts = append(exts, extension.ServerNameOffer{ServerName: serverName})
			}
			body := hello(t, []byte{3, 4}, exts...)
			before := bytes.Clone(body)
			client, err := NewClientHello(list, body)
			require.NoError(t, err)
			require.Equal(t, before, body)
			require.NotEqual(t, client.Inner[2:34], client.Outer[2:34])
			_, outerExts, err := splitHello(client.Outer, false)
			require.NoError(t, err)
			var name extension.ServerNameOffer
			require.NoError(t, name.UnmarshalData(outerExts[extensionIndex(outerExts, extension.TypeServerName)].Data))
			require.Equal(t, "public.example", name.ServerName)
			var offer extension13.ECHClientHello
			require.NoError(t, offer.UnmarshalData(outerExts[extensionIndex(outerExts, extension.TypeEncryptedClientHello)].Data))
			receiver, err := NewRecipient(client.Config, client.Suite, key.Bytes(), offer.Enc)
			require.NoError(t, err)
			aad, err := OuterAAD(client.Outer)
			require.NoError(t, err)
			encoded, err := receiver.Open(aad, offer.Payload)
			require.NoError(t, err)
			decoded, err := DecodeInnerClientHello(encoded, client.Outer)
			require.NoError(t, err)
			require.Equal(t, client.Inner, decoded)
			_, innerExts, err := splitHello(decoded, false)
			require.NoError(t, err)
			var versions extension13.OfferedVersions
			require.NoError(t, versions.UnmarshalData(innerExts[extensionIndex(innerExts, extension.TypeSupportedVersions)].Data))
			require.Equal(t, []protocol.Version{protocol.Version1_3}, versions.Versions)
			outerRandom := bytes.Clone(client.Outer[2:34])
			client.Accepted, client.InitialInner, client.HelloRetryRequest = true, bytes.Clone(client.Inner), []byte{1}
			innerPrefix, retryExts, err := splitHello(client.Inner, false)
			require.NoError(t, err)
			cookie, err := (extension13.Cookie{Cookie: []byte{1}}).MarshalData()
			require.NoError(t, err)
			retryExts = append(retryExts, extension.Raw{Type: extension.TypeCookie, Data: cookie})
			retry, err := appendExtensions(bytes.Clone(innerPrefix), retryExts)
			require.NoError(t, err)
			require.NoError(t, client.RetryClientHello(retry))
			require.Equal(t, outerRandom, client.Outer[2:34])
			_, outerExts, err = splitHello(client.Outer, false)
			require.NoError(t, err)
			require.NoError(t, offer.UnmarshalData(outerExts[extensionIndex(outerExts, extension.TypeEncryptedClientHello)].Data))
			require.Empty(t, offer.Enc)
			aad, err = OuterAAD(client.Outer)
			require.NoError(t, err)
			encoded, err = receiver.Open(aad, offer.Payload)
			require.NoError(t, err)
			decoded, err = DecodeInnerClientHello(encoded, client.Outer)
			require.NoError(t, err)
			require.Equal(t, retry, decoded)
			ciphertext := bytes.Clone(client.Outer)
			require.NoError(t, client.RetryClientHello(retry))
			require.Equal(t, ciphertext, client.Outer)
		})
	}
	for _, typ := range []extension.Type{extension.TypePreSharedKey, extension.TypeEarlyData, extension.TypeCookie} {
		_, err := NewClientHello(list, hello(t, nil, extension.Raw{Type: typ}))
		require.ErrorIs(t, err, ErrUnsupported)
	}
}

func TestProcessClientHello(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	list := configList(key.PublicKey().Bytes())
	body := hello(t, nil, extension.ServerNameOffer{ServerName: "secret.example"}, extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}})
	client, err := NewClientHello(list, body)
	require.NoError(t, err)
	keys := []Key{{Config: list[2:], PrivateKey: key.Bytes()}}
	server, err := ProcessClientHello(client.Outer, keys)
	require.NoError(t, err)
	require.Equal(t, client.Inner, server.Inner)
	require.NotNil(t, server.Recipient)
	server, err = ProcessClientHello(client.Outer, nil)
	require.NoError(t, err)
	require.Equal(t, ServerContext{}, server)
	tampered := bytes.Clone(client.Outer)
	tampered[2] ^= 1
	server, err = ProcessClientHello(tampered, keys)
	require.NoError(t, err)
	require.Equal(t, ServerContext{}, server)
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherList := configList(other.PublicKey().Bytes())
	server, err = ProcessClientHello(client.Outer, append([]Key{{Config: otherList[2:], PrivateKey: other.Bytes()}}, keys...))
	require.NoError(t, err)
	require.Equal(t, client.Inner, server.Inner)
	_, err = ProcessClientHello(client.Outer, []Key{{Config: list[2:], PrivateKey: []byte{1}}})
	var keyAlert *alert.Alert
	require.ErrorAs(t, err, &keyAlert)
	require.Equal(t, alert.InternalError, keyAlert.Description)
	backend, err := ProcessClientHello(client.Inner, nil)
	require.NoError(t, err)
	require.Equal(t, client.Inner, backend.Inner)
	require.Nil(t, backend.Recipient)
	plain, err := ProcessClientHello(body, keys)
	require.NoError(t, err)
	require.Equal(t, ServerContext{}, plain)
	enc, sender, err := NewSender(client.Config, client.Suite)
	require.NoError(t, err)
	offer := extension13.ECHClientHello{KDF: 1, AEAD: 1, Enc: enc, Payload: make([]byte, 17)}
	aad := hello(t, nil, offer)
	offer.Payload, err = sender.Seal(aad, []byte{42})
	require.NoError(t, err)
	_, err = ProcessClientHello(hello(t, nil, offer), keys)
	var fatal *alert.Alert
	require.ErrorAs(t, err, &fatal)
	require.Equal(t, alert.IllegalParameter, fatal.Description)
}

func TestUnadvertisedCipherSuite(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	list := configList(key.PublicKey().Bytes())
	configs, err := ParseConfigList(list)
	require.NoError(t, err)
	config := configs[0]
	suite := CipherSuite{1, 2}
	require.NotContains(t, config.SymmetricCipherSuite, suite)
	publicKey, err := hpke.NewDHKEMPublicKey(key.PublicKey())
	require.NoError(t, err)
	enc, sender, err := hpke.NewSender(publicKey, hpke.HKDFSHA256(), hpke.AES256GCM(), config.info())
	require.NoError(t, err)
	_, err = NewRecipient(config, suite, key.Bytes(), enc)
	require.ErrorIs(t, err, ErrUnsupported)

	inner := hello(t, nil, extension13.ECHClientHello{Type: extension13.ECHClientHelloInner},
		extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}})
	encoded, err := EncodeInnerClientHello(inner, config.MaxNameLength, -1)
	require.NoError(t, err)
	offer := extension13.ECHClientHello{
		KDF: suite.KDFID, AEAD: suite.AEADID, ConfigID: config.ConfigID,
		Enc: enc, Payload: make([]byte, len(encoded)+16),
	}
	aad, err := OuterAAD(hello(t, nil, offer))
	require.NoError(t, err)
	offer.Payload, err = sender.Seal(aad, encoded)
	require.NoError(t, err)
	server, err := ProcessClientHello(hello(t, nil, offer), []Key{{Config: list[2:], PrivateKey: key.Bytes()}})
	require.NoError(t, err)
	require.Equal(t, ServerContext{}, server)
}

func TestECHRetryErrors(t *testing.T) {
	key, setupErr := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, setupErr)
	list := configList(key.PublicKey().Bytes())
	body := hello(t, nil, extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}})
	for _, tc := range []struct {
		name   string
		change func(*extension13.ECHClientHello)
		want   alert.Description
	}{
		{"config ID", func(e *extension13.ECHClientHello) { e.ConfigID++ }, alert.IllegalParameter},
		{"KDF", func(e *extension13.ECHClientHello) { e.KDF++ }, alert.IllegalParameter},
		{"AEAD", func(e *extension13.ECHClientHello) { e.AEAD++ }, alert.IllegalParameter},
		{"encapsulation", func(e *extension13.ECHClientHello) { e.Enc = []byte{1} }, alert.IllegalParameter},
		{"ciphertext", func(e *extension13.ECHClientHello) { e.Payload[0] ^= 1 }, alert.DecryptError},
		{"type switch", func(e *extension13.ECHClientHello) {
			*e = extension13.ECHClientHello{Type: extension13.ECHClientHelloInner}
		}, alert.DecodeError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewClientHello(list, body)
			require.NoError(t, err)
			server, err := ProcessClientHello(client.Outer, []Key{{Config: list[2:], PrivateKey: key.Bytes()}})
			require.NoError(t, err)
			offer := extension13.ECHClientHello{KDF: client.Suite.KDFID, AEAD: client.Suite.AEADID, ConfigID: client.Config.ConfigID, Payload: make([]byte, 16)}
			tc.change(&offer)
			_, err = server.ProcessRetry(hello(t, nil, offer))
			var failure *alert.Alert
			require.ErrorAs(t, err, &failure)
			require.Equal(t, tc.want, failure.Description)
		})
	}
	server, err := ProcessClientHello(hello(t, nil, extension13.ECHClientHello{Type: extension13.ECHClientHelloInner}, extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}}), nil)
	require.NoError(t, err)
	_, err = server.ProcessRetry(body)
	var failure *alert.Alert
	require.ErrorAs(t, err, &failure)
	require.Equal(t, alert.MissingExtension, failure.Description)
	first, err := server.ProcessRetry(server.Inner)
	require.NoError(t, err)
	duplicate, err := server.ProcessRetry(first)
	require.NoError(t, err)
	require.Equal(t, first, duplicate)
	first[2] ^= 1
	_, err = server.ProcessRetry(first)
	require.ErrorAs(t, err, &failure)
	require.Equal(t, alert.IllegalParameter, failure.Description)
}
