// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build go1.26

package flight13

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	"github.com/pion/dtls/v4/internal/ech"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

func TestServerECHNegotiation(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	var builder cryptobyte.Builder
	builder.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(ech.Version)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(1)
			b.AddUint16(32)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key.PublicKey().Bytes()) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
			b.AddUint8(32)
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.example")) })
			b.AddUint16(0)
		})
	})
	list, err := builder.Bytes()
	require.NoError(t, err)
	flightCtx := flight4TestContext(t)
	flightCtx.cfg.ECHKeys = []ech.Key{{Config: list[2:], PrivateKey: key.Bytes()}}
	flightCtx.cfg.InsecureSkipHelloVerify = true
	flightCtx.cfg.LocalCipherSuites = []dtlsconfig.CipherSuite{flightCtx.state.CipherSuite}
	flightCtx.cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519}
	flightCtx.state.LocalVersion = protocol.Version1_3
	flightCtx.cache = dtlsflight.NewCache()
	hello := &handshake.MessageClientHello{
		Version: protocol.Version1_2, CipherSuiteIDs: []uint16{uint16(flightCtx.state.CipherSuite.ID())}, CompressionMethods: dtlsflight.DefaultCompressionMethods(),
		Extensions: []extension.Value{
			&extension.ServerNameOffer{ServerName: "secret.example"},
			&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
			&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(flightCtx.cfg.LocalSignatureSchemes)},
			&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}},
			&extension13.ClientKeyShare{Shares: []extension13.KeyShareEntry{{Group: elliptic.X25519, KeyExchange: flightCtx.state.LocalKeypair.PublicKey}}},
		},
	}
	require.NoError(t, hello.Random.Populate())
	body, err := hello.Marshal()
	require.NoError(t, err)
	client, err := ech.NewClientHello(list, body)
	require.NoError(t, err)
	outer := &handshake.MessageClientHello{}
	require.NoError(t, outer.Unmarshal(client.Outer))
	raw := marshalProtectedTestHandshake(t, 0, outer)
	before := bytes.Clone(raw)
	flightCtx.cache.Push(raw, 0, 0, handshake.TypeClientHello, true)
	called := false
	flightCtx.inboundHandshakeHandler = func(_ dtlsconfig.CipherSuite, items []dtlsflight.DecodedHandshakeCacheItem) error {
		called = true
		require.NoError(t, items[0].Validate())
		require.Equal(t, client.Inner, items[0].Raw.Data[handshake.HeaderLength:])

		return nil
	}
	next, dtlsAlert, err := flight0Parse(t.Context(), nil, flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Equal(t, Flight4, next)
	require.True(t, called)
	require.Equal(t, "secret.example", flightCtx.state.ServerName)
	require.Equal(t, hello.Random.MarshalFixed(), flightCtx.state.RemoteRandom.MarshalFixed())
	require.Equal(t, before, raw)
	packets, dtlsAlert, err := flight4Generate(nil, flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	response, ok := packets[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	serverHello, ok := response.Message.(*handshake.MessageServerHello)
	require.True(t, ok)
	serverBody, err := serverHello.Marshal()
	require.NoError(t, err)
	confirmation, err := ech.AcceptanceConfirmation(flightCtx.state.CipherSuite.HashFunc(), client.Inner, serverBody)
	require.NoError(t, err)
	require.Equal(t, confirmation, serverBody[26:34])
	repeated, _, err := flight4Generate(nil, flightCtx)
	require.NoError(t, err)
	repeatedBody, err := repeated[0].Content.Marshal()
	require.NoError(t, err)
	initialBody, err := packets[0].Content.Marshal()
	require.NoError(t, err)
	require.Equal(t, initialBody, repeatedBody)
	flightCtx.cfg.InsecureSkipHelloVerify = false
	next, dtlsAlert, err = flight0Parse(t.Context(), nil, flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Equal(t, Flight2, next)
}
