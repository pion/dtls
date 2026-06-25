// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandshakeCacheSinglePush(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Rule     []dtlsflight.HandshakeCachePullRule
		Input    []dtlsflight.HandshakeCacheItem
		Expected []byte
	}{
		{
			Name: "Single Push",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 0, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 0, Epoch: 0, IsClient: true, Optional: false},
			},
			Expected: []byte{0x00},
		},
		{
			Name: "Multi Push",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 0, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: 2, IsClient: true, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 0, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 2, Epoch: 0, IsClient: true, Optional: false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Rules set order",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 2, IsClient: true, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
				{Typ: 0, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 0, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 2, Epoch: 0, IsClient: true, Optional: false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},

		{
			Name: "Multi Push, Dupe Seqnum",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 0, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 0, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
			},
			Expected: []byte{0x00, 0x01},
		},
		{
			Name: "Multi Push, Dupe Seqnum Client/Server",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 0, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: 1, IsClient: false, Epoch: 0, MessageSequence: 1, Data: []byte{0x02}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 0, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 1, Epoch: 0, IsClient: false, Optional: false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Dupe Seqnum with Unique HandshakeType",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 2, IsClient: true, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: 3, IsClient: false, Epoch: 0, MessageSequence: 0, Data: []byte{0x02}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 2, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 3, Epoch: 0, IsClient: false, Optional: false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Wrong epoch",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: 1, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: 2, IsClient: true, Epoch: 1, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: 2, IsClient: true, Epoch: 0, MessageSequence: 2, Data: []byte{0x11}},
				{Typ: 3, IsClient: false, Epoch: 0, MessageSequence: 0, Data: []byte{0x02}},
				{Typ: 3, IsClient: false, Epoch: 1, MessageSequence: 0, Data: []byte{0x12}},
				{Typ: 3, IsClient: false, Epoch: 2, MessageSequence: 0, Data: []byte{0x12}},
			},
			Rule: []dtlsflight.HandshakeCachePullRule{
				{Typ: 1, Epoch: 0, IsClient: true, Optional: false},
				{Typ: 2, Epoch: 1, IsClient: true, Optional: false},
				{Typ: 3, Epoch: 0, IsClient: false, Optional: false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
	} {
		h := dtlsflight.NewCache()
		for _, i := range test.Input {
			h.Push(i.Data, i.Epoch, i.MessageSequence, i.Typ, i.IsClient)
		}
		verifyData := h.PullAndMerge(test.Rule...)
		assert.Equal(t, test.Expected, verifyData)
	}
}

func TestHandshakeCacheFullPullMapItemsReturnsAcceptedRawItems(t *testing.T) {
	cipherSuiteID := uint16(TLS_AES_128_GCM_SHA256)
	rawClientHello := marshalHandshakeCacheTestMessage(t, 0, &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		CipherSuiteIDs:     []uint16{uint16(TLS_AES_128_GCM_SHA256)},
		CompressionMethods: defaultCompressionMethods(),
	})
	rawServerHello := marshalHandshakeCacheTestMessage(t, 1, &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: defaultCompressionMethods()[0],
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, 0, 1, handshake.TypeServerHello, false)
	cache.Push(rawClientHello, 0, 0, handshake.TypeClientHello, true)

	seq, msgs, items, ok := cache.FullPullMapItems(0, nil,
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeClientHello, Epoch: 0, IsClient: true, Optional: false},  //nolint:lll
		dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeServerHello, Epoch: 0, IsClient: false, Optional: false}, //nolint:lll
	)

	require.True(t, ok)
	assert.Equal(t, 2, seq)
	require.IsType(t, &handshake.MessageClientHello{}, msgs[handshake.TypeClientHello])
	require.IsType(t, &handshake.MessageServerHello{}, msgs[handshake.TypeServerHello])
	require.Len(t, items, 2)
	assert.Equal(t, rawClientHello, items[0].Data)
	assert.Equal(t, rawServerHello, items[1].Data)
}

func marshalHandshakeCacheTestMessage(t *testing.T, seq uint16, message handshake.Message) []byte {
	t.Helper()

	raw, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: seq},
		Message: message,
	}).Marshal()
	require.NoError(t, err)

	return raw
}

func TestHandshakeCacheSessionHash(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Rule     []dtlsflight.HandshakeCachePullRule
		Input    []dtlsflight.HandshakeCacheItem
		Expected []byte
	}{
		{
			Name: "Standard Handshake",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: handshake.TypeClientHello, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: handshake.TypeServerHello, IsClient: false, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: handshake.TypeCertificate, IsClient: false, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
				{Typ: handshake.TypeServerKeyExchange, IsClient: false, Epoch: 0, MessageSequence: 3, Data: []byte{0x03}},
				{Typ: handshake.TypeServerHelloDone, IsClient: false, Epoch: 0, MessageSequence: 4, Data: []byte{0x04}},
				{Typ: handshake.TypeClientKeyExchange, IsClient: true, Epoch: 0, MessageSequence: 5, Data: []byte{0x05}},
			},
			Expected: []byte{
				0x17, 0xe8, 0x8d, 0xb1, 0x87, 0xaf, 0xd6, 0x2c, 0x16, 0xe5, 0xde, 0xbf, 0x3e, 0x65, 0x27, 0xcd,
				0x00, 0x6b, 0xc0, 0x12, 0xbc, 0x90, 0xb5, 0x1a, 0x81, 0x0c, 0xd8, 0x0c, 0x2d, 0x51, 0x1f, 0x43,
			},
		},
		{
			Name: "Handshake With Client Cert Request",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: handshake.TypeClientHello, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: handshake.TypeServerHello, IsClient: false, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: handshake.TypeCertificate, IsClient: false, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
				{Typ: handshake.TypeServerKeyExchange, IsClient: false, Epoch: 0, MessageSequence: 3, Data: []byte{0x03}},
				{Typ: handshake.TypeCertificateRequest, IsClient: false, Epoch: 0, MessageSequence: 4, Data: []byte{0x04}},
				{Typ: handshake.TypeServerHelloDone, IsClient: false, Epoch: 0, MessageSequence: 5, Data: []byte{0x05}},
				{Typ: handshake.TypeClientKeyExchange, IsClient: true, Epoch: 0, MessageSequence: 6, Data: []byte{0x06}},
			},
			Expected: []byte{
				0x57, 0x35, 0x5a, 0xc3, 0x30, 0x3c, 0x14, 0x8f, 0x11, 0xae, 0xf7, 0xcb, 0x17, 0x94, 0x56, 0xb9,
				0x23, 0x2c, 0xde, 0x33, 0xa8, 0x18, 0xdf, 0xda, 0x2c, 0x2f, 0xcb, 0x93, 0x25, 0x74, 0x9a, 0x6b,
			},
		},
		{
			Name: "Handshake Ignores after ClientKeyExchange",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: handshake.TypeClientHello, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: handshake.TypeServerHello, IsClient: false, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: handshake.TypeCertificate, IsClient: false, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
				{Typ: handshake.TypeServerKeyExchange, IsClient: false, Epoch: 0, MessageSequence: 3, Data: []byte{0x03}},
				{Typ: handshake.TypeCertificateRequest, IsClient: false, Epoch: 0, MessageSequence: 4, Data: []byte{0x04}},
				{Typ: handshake.TypeServerHelloDone, IsClient: false, Epoch: 0, MessageSequence: 5, Data: []byte{0x05}},
				{Typ: handshake.TypeClientKeyExchange, IsClient: true, Epoch: 0, MessageSequence: 6, Data: []byte{0x06}},
				{Typ: handshake.TypeCertificateVerify, IsClient: true, Epoch: 0, MessageSequence: 7, Data: []byte{0x07}},
				{Typ: handshake.TypeFinished, IsClient: true, Epoch: 1, MessageSequence: 7, Data: []byte{0x08}},
				{Typ: handshake.TypeFinished, IsClient: false, Epoch: 1, MessageSequence: 7, Data: []byte{0x09}},
			},
			Expected: []byte{
				0x57, 0x35, 0x5a, 0xc3, 0x30, 0x3c, 0x14, 0x8f, 0x11, 0xae, 0xf7, 0xcb, 0x17, 0x94, 0x56, 0xb9,
				0x23, 0x2c, 0xde, 0x33, 0xa8, 0x18, 0xdf, 0xda, 0x2c, 0x2f, 0xcb, 0x93, 0x25, 0x74, 0x9a, 0x6b,
			},
		},
		{
			Name: "Handshake Ignores wrong epoch",
			Input: []dtlsflight.HandshakeCacheItem{
				{Typ: handshake.TypeClientHello, IsClient: true, Epoch: 0, MessageSequence: 0, Data: []byte{0x00}},
				{Typ: handshake.TypeServerHello, IsClient: false, Epoch: 0, MessageSequence: 1, Data: []byte{0x01}},
				{Typ: handshake.TypeCertificate, IsClient: false, Epoch: 0, MessageSequence: 2, Data: []byte{0x02}},
				{Typ: handshake.TypeServerKeyExchange, IsClient: false, Epoch: 0, MessageSequence: 3, Data: []byte{0x03}},
				{Typ: handshake.TypeCertificateRequest, IsClient: false, Epoch: 0, MessageSequence: 4, Data: []byte{0x04}},
				{Typ: handshake.TypeServerHelloDone, IsClient: false, Epoch: 0, MessageSequence: 5, Data: []byte{0x05}},
				{Typ: handshake.TypeClientKeyExchange, IsClient: true, Epoch: 0, MessageSequence: 6, Data: []byte{0x06}},
				{Typ: handshake.TypeCertificateVerify, IsClient: true, Epoch: 0, MessageSequence: 7, Data: []byte{0x07}},
				{Typ: handshake.TypeFinished, IsClient: true, Epoch: 0, MessageSequence: 7, Data: []byte{0xf0}},
				{Typ: handshake.TypeFinished, IsClient: false, Epoch: 0, MessageSequence: 7, Data: []byte{0xf1}},
				{Typ: handshake.TypeFinished, IsClient: true, Epoch: 1, MessageSequence: 7, Data: []byte{0x08}},
				{Typ: handshake.TypeFinished, IsClient: false, Epoch: 1, MessageSequence: 7, Data: []byte{0x09}},
				{Typ: handshake.TypeFinished, IsClient: true, Epoch: 0, MessageSequence: 7, Data: []byte{0xf0}},
				{Typ: handshake.TypeFinished, IsClient: false, Epoch: 0, MessageSequence: 7, Data: []byte{0xf1}},
			},
			Expected: []byte{
				0x57, 0x35, 0x5a, 0xc3, 0x30, 0x3c, 0x14, 0x8f, 0x11, 0xae, 0xf7, 0xcb, 0x17, 0x94, 0x56, 0xb9,
				0x23, 0x2c, 0xde, 0x33, 0xa8, 0x18, 0xdf, 0xda, 0x2c, 0x2f, 0xcb, 0x93, 0x25, 0x74, 0x9a, 0x6b,
			},
		},
	} {
		h := dtlsflight.NewCache()
		for _, i := range test.Input {
			h.Push(i.Data, i.Epoch, i.MessageSequence, i.Typ, i.IsClient)
		}

		cipherSuite := ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}
		verifyData, err := h.SessionHash(cipherSuite.HashFunc(), 0)
		assert.NoError(t, err)
		assert.Equal(t, test.Expected, verifyData, "handshakeCacheSessionHash")
	}
}
