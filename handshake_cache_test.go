// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
)

func TestHandshakeCacheSinglePush(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Rule     []handshakeCachePullRule
		Input    []handshakeCacheItem
		Expected []byte
	}{
		{
			Name: "Single Push",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
			},
			Rule: []handshakeCachePullRule{
				{0, 0, true, false},
			},
			Expected: []byte{0x00},
		},
		{
			Name: "Multi Push",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
				{1, true, 0, 1, []byte{0x01}},
				{2, true, 0, 2, []byte{0x02}},
			},
			Rule: []handshakeCachePullRule{
				{0, 0, true, false},
				{1, 0, true, false},
				{2, 0, true, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Rules set order",
			Input: []handshakeCacheItem{
				{2, true, 0, 2, []byte{0x02}},
				{0, true, 0, 0, []byte{0x00}},
				{1, true, 0, 1, []byte{0x01}},
			},
			Rule: []handshakeCachePullRule{
				{0, 0, true, false},
				{1, 0, true, false},
				{2, 0, true, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},

		{
			Name: "Multi Push, Dupe Seqnum",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
				{1, true, 0, 1, []byte{0x01}},
				{1, true, 0, 1, []byte{0x01}},
			},
			Rule: []handshakeCachePullRule{
				{0, 0, true, false},
				{1, 0, true, false},
			},
			Expected: []byte{0x00, 0x01},
		},
		{
			Name: "Multi Push, Dupe Seqnum Client/Server",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
				{1, true, 0, 1, []byte{0x01}},
				{1, false, 0, 1, []byte{0x02}},
			},
			Rule: []handshakeCachePullRule{
				{0, 0, true, false},
				{1, 0, true, false},
				{1, 0, false, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Dupe Seqnum with Unique HandshakeType",
			Input: []handshakeCacheItem{
				{1, true, 0, 0, []byte{0x00}},
				{2, true, 0, 1, []byte{0x01}},
				{3, false, 0, 0, []byte{0x02}},
			},
			Rule: []handshakeCachePullRule{
				{1, 0, true, false},
				{2, 0, true, false},
				{3, 0, false, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Wrong epoch",
			Input: []handshakeCacheItem{
				{1, true, 0, 0, []byte{0x00}},
				{2, true, 1, 1, []byte{0x01}},
				{2, true, 0, 2, []byte{0x11}},
				{3, false, 0, 0, []byte{0x02}},
				{3, false, 1, 0, []byte{0x12}},
				{3, false, 2, 0, []byte{0x12}},
			},
			Rule: []handshakeCachePullRule{
				{1, 0, true, false},
				{2, 1, true, false},
				{3, 0, false, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
	} {
		h := newHandshakeCache()
		for _, i := range test.Input {
			assert.NoError(t, h.push(i.data, i.epoch, i.messageSequence, i.typ, i.isClient))
		}
		verifyData := h.pullAndMerge(test.Rule...)
		assert.Equal(t, test.Expected, verifyData)
	}
}

func TestHandshakeCacheSessionHash(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Rule     []handshakeCachePullRule
		Input    []handshakeCacheItem
		Expected []byte
	}{
		{
			Name: "Standard Handshake",
			Input: []handshakeCacheItem{
				{handshake.TypeClientHello, true, 0, 0, []byte{0x00}},
				{handshake.TypeServerHello, false, 0, 1, []byte{0x01}},
				{handshake.TypeCertificate, false, 0, 2, []byte{0x02}},
				{handshake.TypeServerKeyExchange, false, 0, 3, []byte{0x03}},
				{handshake.TypeServerHelloDone, false, 0, 4, []byte{0x04}},
				{handshake.TypeClientKeyExchange, true, 0, 5, []byte{0x05}},
			},
			Expected: []byte{
				0x17, 0xe8, 0x8d, 0xb1, 0x87, 0xaf, 0xd6, 0x2c, 0x16, 0xe5, 0xde, 0xbf, 0x3e, 0x65, 0x27, 0xcd,
				0x00, 0x6b, 0xc0, 0x12, 0xbc, 0x90, 0xb5, 0x1a, 0x81, 0x0c, 0xd8, 0x0c, 0x2d, 0x51, 0x1f, 0x43,
			},
		},
		{
			Name: "Handshake With Client Cert Request",
			Input: []handshakeCacheItem{
				{handshake.TypeClientHello, true, 0, 0, []byte{0x00}},
				{handshake.TypeServerHello, false, 0, 1, []byte{0x01}},
				{handshake.TypeCertificate, false, 0, 2, []byte{0x02}},
				{handshake.TypeServerKeyExchange, false, 0, 3, []byte{0x03}},
				{handshake.TypeCertificateRequest, false, 0, 4, []byte{0x04}},
				{handshake.TypeServerHelloDone, false, 0, 5, []byte{0x05}},
				{handshake.TypeClientKeyExchange, true, 0, 6, []byte{0x06}},
			},
			Expected: []byte{
				0x57, 0x35, 0x5a, 0xc3, 0x30, 0x3c, 0x14, 0x8f, 0x11, 0xae, 0xf7, 0xcb, 0x17, 0x94, 0x56, 0xb9,
				0x23, 0x2c, 0xde, 0x33, 0xa8, 0x18, 0xdf, 0xda, 0x2c, 0x2f, 0xcb, 0x93, 0x25, 0x74, 0x9a, 0x6b,
			},
		},
		{
			Name: "Handshake Ignores after ClientKeyExchange",
			Input: []handshakeCacheItem{
				{handshake.TypeClientHello, true, 0, 0, []byte{0x00}},
				{handshake.TypeServerHello, false, 0, 1, []byte{0x01}},
				{handshake.TypeCertificate, false, 0, 2, []byte{0x02}},
				{handshake.TypeServerKeyExchange, false, 0, 3, []byte{0x03}},
				{handshake.TypeCertificateRequest, false, 0, 4, []byte{0x04}},
				{handshake.TypeServerHelloDone, false, 0, 5, []byte{0x05}},
				{handshake.TypeClientKeyExchange, true, 0, 6, []byte{0x06}},
				{handshake.TypeCertificateVerify, true, 0, 7, []byte{0x07}},
				{handshake.TypeFinished, true, 1, 7, []byte{0x08}},
				{handshake.TypeFinished, false, 1, 7, []byte{0x09}},
			},
			Expected: []byte{
				0x57, 0x35, 0x5a, 0xc3, 0x30, 0x3c, 0x14, 0x8f, 0x11, 0xae, 0xf7, 0xcb, 0x17, 0x94, 0x56, 0xb9,
				0x23, 0x2c, 0xde, 0x33, 0xa8, 0x18, 0xdf, 0xda, 0x2c, 0x2f, 0xcb, 0x93, 0x25, 0x74, 0x9a, 0x6b,
			},
		},
		{
			Name: "Handshake Ignores wrong epoch",
			Input: []handshakeCacheItem{
				{handshake.TypeClientHello, true, 0, 0, []byte{0x00}},
				{handshake.TypeServerHello, false, 0, 1, []byte{0x01}},
				{handshake.TypeCertificate, false, 0, 2, []byte{0x02}},
				{handshake.TypeServerKeyExchange, false, 0, 3, []byte{0x03}},
				{handshake.TypeCertificateRequest, false, 0, 4, []byte{0x04}},
				{handshake.TypeServerHelloDone, false, 0, 5, []byte{0x05}},
				{handshake.TypeClientKeyExchange, true, 0, 6, []byte{0x06}},
				{handshake.TypeCertificateVerify, true, 0, 7, []byte{0x07}},
				{handshake.TypeFinished, true, 0, 7, []byte{0xf0}},
				{handshake.TypeFinished, false, 0, 7, []byte{0xf1}},
				{handshake.TypeFinished, true, 1, 7, []byte{0x08}},
				{handshake.TypeFinished, false, 1, 7, []byte{0x09}},
				{handshake.TypeFinished, true, 0, 7, []byte{0xf0}},
				{handshake.TypeFinished, false, 0, 7, []byte{0xf1}},
			},
			Expected: []byte{
				0x57, 0x35, 0x5a, 0xc3, 0x30, 0x3c, 0x14, 0x8f, 0x11, 0xae, 0xf7, 0xcb, 0x17, 0x94, 0x56, 0xb9,
				0x23, 0x2c, 0xde, 0x33, 0xa8, 0x18, 0xdf, 0xda, 0x2c, 0x2f, 0xcb, 0x93, 0x25, 0x74, 0x9a, 0x6b,
			},
		},
	} {
		h := newHandshakeCache()
		for _, i := range test.Input {
			assert.NoError(t, h.push(i.data, i.epoch, i.messageSequence, i.typ, i.isClient))
		}

		cipherSuite := ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}
		verifyData, err := h.sessionHash(cipherSuite.HashFunc(), 0)
		assert.NoError(t, err)
		assert.Equal(t, test.Expected, verifyData, "handshakeCacheSessionHash")
	}
}

func TestClientHelloRetransmit(t *testing.T) {
	const messageLength = 4

	makePacket := func(sequence uint16, offset uint32, fragment string) []byte {
		t.Helper()
		fragmentLength := len(fragment)
		if fragmentLength > messageLength {
			assert.Fail(t, "test fragment exceeds the ClientHello length")

			return nil
		}

		header := handshake.Header{
			Type:            handshake.TypeClientHello,
			MessageSequence: sequence,
			Length:          messageLength,
			FragmentOffset:  offset,
			FragmentLength:  uint32(fragmentLength),
		}
		raw, err := header.Marshal()
		assert.NoError(t, err)

		record := recordlayer.Header{
			ContentType: protocol.ContentTypeHandshake,
			Version:     protocol.Version1_2,
			ContentLen:  handshake.HeaderLength + uint16(fragmentLength),
		}
		prefix, err := record.Marshal()
		assert.NoError(t, err)

		return append(append(prefix, raw...), fragment...)
	}

	original := makePacket(1, 0, "abcd")
	firstFragment := makePacket(1, 0, "ab")
	lastFragment := makePacket(1, 2, "cd")

	type step struct {
		packet       []byte
		wantComplete bool
	}

	for _, testCase := range []struct {
		name  string
		steps []step
	}{
		{
			name: "complete",
			steps: []step{
				{packet: original, wantComplete: true},
				{packet: original, wantComplete: true},
			},
		},
		{
			name:  "older flight",
			steps: []step{{packet: makePacket(0, 0, "abcd")}},
		},
		{
			name:  "changed content",
			steps: []step{{packet: makePacket(1, 0, "abce")}},
		},
		{
			name: "fragmented",
			steps: []step{
				{packet: firstFragment},
				{packet: lastFragment, wantComplete: true},
			},
		},
		{
			name: "reordered",
			steps: []step{
				{packet: lastFragment},
				{packet: firstFragment, wantComplete: true},
			},
		},
		{
			name: "repeated partial",
			steps: []step{
				{packet: firstFragment},
				{packet: firstFragment},
			},
		},
		{
			name:  "truncated",
			steps: []step{{packet: original[:len(original)-1]}},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cache := newHandshakeCache()
			assert.NoError(t, cache.push(original[recordlayer.FixedHeaderSize:], 0, 1, handshake.TypeClientHello, true))

			for i, step := range testCase.steps {
				assert.Equal(t, step.wantComplete, cache.isClientHelloRetransmit(step.packet), "step %d", i)
			}
		})
	}
}

func TestHandshakeCacheLimits(t *testing.T) {
	t.Run("duplicates preserve original transcript", func(t *testing.T) {
		cache := newHandshakeCache()
		original := []byte{1, 2, 3}
		assert.NoError(t, cache.push(original, 1, 4, handshake.TypeFinished, true))
		original[0] = 9
		for range handshakeCacheMaxCount + 1 {
			assert.NoError(t, cache.push([]byte{4}, 1, 4, handshake.TypeCertificate, true))
		}
		assert.Len(t, cache.cache, 1)
		assert.Equal(t, []byte{1, 2, 3}, cache.cache[0].data)
		assert.Equal(t, 3, cache.size)
		assert.NoError(t, cache.push([]byte{4}, 1, 4, handshake.TypeFinished, false))
		assert.NoError(t, cache.push([]byte{4}, 2, 4, handshake.TypeFinished, true))
		assert.Len(t, cache.cache, 3)
	})
	t.Run("empty messages have a count limit", func(t *testing.T) {
		cache := newHandshakeCache()
		for i := range uint16(handshakeCacheMaxCount) {
			assert.NoError(t, cache.push(nil, 0, i, handshake.TypeServerHelloDone, false))
		}
		err := cache.push(nil, 0, handshakeCacheMaxCount, handshake.TypeServerHelloDone, false)
		assert.ErrorIs(t, err, errHandshakeCacheOverflow)
		assert.Len(t, cache.cache, handshakeCacheMaxCount)
	})
	t.Run("payload bytes have a limit", func(t *testing.T) {
		cache := newHandshakeCache()
		assert.NoError(t, cache.push(make([]byte, handshakeCacheMaxSize), 0, 0, handshake.TypeCertificate, false))
		assert.ErrorIs(t, cache.push([]byte{1}, 0, 1, handshake.TypeCertificate, true), errHandshakeCacheOverflow)
		assert.Len(t, cache.cache, 1)
		assert.Equal(t, handshakeCacheMaxSize, cache.size)
	})
}

// Exercise both OOM paths: fresh inbound messages across sequence wraparound,
// and repeated outbound Finished caching after handshake completion.
func TestHandshakeCachePostHandshakeFlood(t *testing.T) {
	conn := &Conn{
		handshakeCache:         newHandshakeCache(),
		fragmentBuffer:         newFragmentBuffer(),
		log:                    logging.NewDefaultLoggerFactory().NewLogger("dtls"),
		replayProtectionWindow: 64,
	}
	assert.NoError(t, conn.handshakeCache.push([]byte{1}, 1, 0, handshake.TypeFinished, false))
	assert.True(t, conn.setHandshakeCompletedSuccessfully())
	for i := range uint64(1<<16 + 1) {
		header := handshake.Header{
			Type:            handshake.TypeServerHelloDone,
			MessageSequence: uint16(i), //nolint:gosec // Exercise wraparound.
		}
		payload, err := header.Marshal()
		assert.NoError(t, err)
		record := recordlayer.Header{
			ContentType:    protocol.ContentTypeHandshake,
			Version:        protocol.Version1_2,
			SequenceNumber: i,
			ContentLen:     handshake.HeaderLength,
		}
		raw, err := record.Marshal()
		assert.NoError(t, err)
		hs, _, alert, err := conn.handleIncomingPacket(context.Background(), append(raw, payload...), nil, false)
		assert.NoError(t, err)
		assert.Nil(t, alert)
		assert.True(t, hs)
	}
	finished := &handshake.Handshake{Message: &handshake.MessageFinished{VerifyData: []byte{1}}}
	pkt := &packet{record: &recordlayer.RecordLayer{
		Header: recordlayer.Header{Version: protocol.Version1_2, Epoch: 1}, Content: finished,
	}}
	for range handshakeCacheMaxCount + 1 {
		assert.NoError(t, conn.cacheHandshakePacket(pkt, finished))
	}
	assert.Len(t, conn.handshakeCache.cache, 1)
	assert.Equal(t, []byte{1}, conn.handshakeCache.cache[0].data)
	assert.Equal(t, 1, conn.handshakeCache.size)
}

func TestHandshakeCacheOverflowAbortsHandshake(t *testing.T) {
	conn := &Conn{
		handshakeCache:         newHandshakeCache(),
		fragmentBuffer:         newFragmentBuffer(),
		log:                    logging.NewDefaultLoggerFactory().NewLogger("dtls"),
		replayProtectionWindow: 64,
	}
	for i := range uint16(handshakeCacheMaxCount) {
		assert.NoError(t, conn.handshakeCache.push(nil, 0, i+1, handshake.TypeClientHello, true))
	}
	message := &handshake.Handshake{Message: &handshake.MessageServerHelloDone{}}
	record := &recordlayer.RecordLayer{
		Header:  recordlayer.Header{Version: protocol.Version1_2},
		Content: message,
	}
	raw, err := record.Marshal()
	assert.NoError(t, err)
	_, _, fatalAlert, err := conn.handleIncomingPacket(context.Background(), raw, nil, false)
	assert.ErrorIs(t, err, errHandshakeCacheOverflow)
	assert.NotNil(t, fatalAlert)
	assert.Len(t, conn.handshakeCache.cache, handshakeCacheMaxCount)
	err = conn.cacheHandshakePacket(&packet{record: record}, message)
	assert.ErrorIs(t, err, errHandshakeCacheOverflow)
}
