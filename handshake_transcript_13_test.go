// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
)

func TestCanonicalHandshake13(t *testing.T) {
	const bodyLen = 3

	body := []byte{0xaa, 0xbb, 0xcc}
	raw := makeRawHandshake13(t, handshake.Header{
		Type:            handshake.TypeClientHello,
		Length:          bodyLen,
		MessageSequence: 7,
		FragmentLength:  bodyLen,
	}, body)

	canonical, err := canonicalHandshake13(raw)
	assert.NoError(t, err)
	assert.Equal(t, []byte{
		byte(handshake.TypeClientHello), 0x00, 0x00, 0x03,
		0xaa, 0xbb, 0xcc,
	}, canonical)
}

func TestCanonicalHandshake13RejectsInvalidMessages(t *testing.T) {
	const bodyLen = 2

	body := []byte{0xaa, 0xbb}

	for _, test := range []struct {
		name string
		raw  []byte
		err  error
	}{
		{
			name: "too small",
			raw:  []byte{byte(handshake.TypeClientHello)},
			err:  errBufferTooSmall,
		},
		{
			name: "fragment offset",
			raw: makeRawHandshake13(t, handshake.Header{
				Type:            handshake.TypeClientHello,
				Length:          bodyLen,
				MessageSequence: 1,
				FragmentOffset:  1,
				FragmentLength:  bodyLen,
			}, body),
			err: errInvalidHandshakeTranscriptMessage,
		},
		{
			name: "fragment length",
			raw: makeRawHandshake13(t, handshake.Header{
				Type:            handshake.TypeClientHello,
				Length:          bodyLen,
				MessageSequence: 1,
				FragmentLength:  bodyLen - 1,
			}, body),
			err: errInvalidHandshakeTranscriptMessage,
		},
		{
			name: "body length",
			raw: makeRawHandshake13(t, handshake.Header{
				Type:            handshake.TypeClientHello,
				Length:          bodyLen + 1,
				MessageSequence: 1,
				FragmentLength:  bodyLen + 1,
			}, body),
			err: errInvalidHandshakeTranscriptMessage,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := canonicalHandshake13(test.raw)
			assert.ErrorIs(t, err, test.err)
		})
	}
}

func TestHandshakeTranscript13DeferredHashSelection(t *testing.T) {
	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01, 0x02})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x03, 0x04})
	expectedClientHello := append([]byte(nil), clientHello...)

	transcript := newHandshakeTranscript13()
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
	clientHello[len(clientHello)-1] = 0xff
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello))

	assert.NoError(t, transcript.selectHash(sha256.New))

	sum, err := transcript.sum()
	assert.NoError(t, err)
	assert.Equal(t, hashTranscript13(expectedClientHello, serverHello), sum)
}

func TestHandshakeTranscript13RejectsSumBeforeHashSelection(t *testing.T) {
	transcript := newHandshakeTranscript13()

	_, err := transcript.sum()
	assert.ErrorIs(t, err, errHandshakeTranscriptHashNotSelected)
}

func TestHandshakeTranscript13RejectsHashReselection(t *testing.T) {
	transcript := newHandshakeTranscript13()
	assert.NoError(t, transcript.selectHash(sha256.New))

	err := transcript.selectHash(sha256.New)
	assert.ErrorIs(t, err, errHandshakeTranscriptHashAlreadySelected)
}

func TestHandshakeTranscript13DuplicateHandling(t *testing.T) {
	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	changedClientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x02})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x03})

	transcript := newHandshakeTranscript13()
	assert.NoError(t, transcript.selectHash(sha256.New))
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))

	err := transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, changedClientHello)
	assert.ErrorIs(t, err, errHandshakeTranscriptMessageChanged)

	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello))

	sum, err := transcript.sum()
	assert.NoError(t, err)
	assert.Equal(t, hashTranscript13(clientHello, serverHello), sum)
}

func TestHandshakeTranscript13RejectsInvalidCanonicalMessage(t *testing.T) {
	transcript := newHandshakeTranscript13()

	err := transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, []byte{
		byte(handshake.TypeClientHello), 0x00, 0x00, 0x02, 0x01,
	})
	assert.ErrorIs(t, err, errInvalidHandshakeTranscriptMessage)
}

func TestHandshakeTranscript13HelloRetryRequest(t *testing.T) {
	clientHello1 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	helloRetryRequest := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	clientHello2 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x03})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x04})

	transcript := newHandshakeTranscript13()
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello1))
	assert.NoError(t, transcript.selectHash(sha256.New))
	assert.NoError(t, transcript.applyHelloRetryRequest())
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, helloRetryRequest))
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13, seq: 1}, clientHello2))
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13, seq: 1}, serverHello))

	clientHello1Hash := hashTranscript13(clientHello1)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	expected := hashTranscript13(messageHash, helloRetryRequest, clientHello2, serverHello)

	sum, err := transcript.sum()
	assert.NoError(t, err)
	assert.Equal(t, expected, sum)
	assert.Equal(t, "MessageHash", handshake.TypeMessageHash.String())
}

func TestHandshakeTranscript13HelloRetryRequestBinderFork(t *testing.T) {
	clientHello1 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	helloRetryRequest := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	placeholderBinder := make([]byte, sha256.Size)
	_, truncatedClientHello2 := pskClientHelloTranscript13(t, placeholderBinder)

	transcript := newHandshakeTranscript13()
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello1))
	assert.NoError(t, transcript.selectHash(sha256.New))
	assert.NoError(t, transcript.applyHelloRetryRequest())
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, helloRetryRequest))

	mainSumBefore, err := transcript.sum()
	assert.NoError(t, err)
	assert.ErrorIs(t, validateCanonicalHandshake13(truncatedClientHello2), errInvalidHandshakeTranscriptMessage)

	binderTranscriptHash, err := transcript.sumWithSuffix(truncatedClientHello2)
	assert.NoError(t, err)

	clientHello1Hash := hashTranscript13(clientHello1)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	expectedBinderTranscriptHash := hashTranscript13(messageHash, helloRetryRequest, truncatedClientHello2)
	assert.Equal(t, expectedBinderTranscriptHash, binderTranscriptHash)

	binderKey := []byte("binder key")
	binder := hmacSHA25613(binderKey, binderTranscriptHash)
	expectedBinder := hmacSHA25613(binderKey, expectedBinderTranscriptHash)
	assert.Equal(t, expectedBinder, binder)

	mainSumAfter, err := transcript.sum()
	assert.NoError(t, err)
	assert.Equal(t, mainSumBefore, mainSumAfter)

	clientHello2, truncatedClientHello2WithBinder := pskClientHelloTranscript13(t, binder)
	assert.Equal(t, truncatedClientHello2, truncatedClientHello2WithBinder)
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13, seq: 1}, clientHello2))

	sum, err := transcript.sum()
	assert.NoError(t, err)
	assert.Equal(t, hashTranscript13(messageHash, helloRetryRequest, clientHello2), sum)
}

func TestHandshakeTranscript13HelloRetryRequestErrors(t *testing.T) {
	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})

	t.Run("hash not selected", func(t *testing.T) {
		transcript := newHandshakeTranscript13()
		assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))

		err := transcript.applyHelloRetryRequest()
		assert.ErrorIs(t, err, errHandshakeTranscriptHashNotSelected)
	})

	t.Run("not first client hello only", func(t *testing.T) {
		transcript := newHandshakeTranscript13()
		assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
		assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello))
		assert.NoError(t, transcript.selectHash(sha256.New))

		err := transcript.applyHelloRetryRequest()
		assert.ErrorIs(t, err, errHandshakeTranscriptHelloRetryRequestInvalid)
	})

	t.Run("server message", func(t *testing.T) {
		transcript := newHandshakeTranscript13()
		assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptServer13}, serverHello))
		assert.NoError(t, transcript.selectHash(sha256.New))

		err := transcript.applyHelloRetryRequest()
		assert.ErrorIs(t, err, errHandshakeTranscriptHelloRetryRequestInvalid)
	})

	t.Run("already applied", func(t *testing.T) {
		transcript := newHandshakeTranscript13()
		assert.NoError(t, transcript.appendCanonical(transcriptMessageID13{sender: transcriptClient13}, clientHello))
		assert.NoError(t, transcript.selectHash(sha256.New))
		assert.NoError(t, transcript.applyHelloRetryRequest())

		err := transcript.applyHelloRetryRequest()
		assert.ErrorIs(t, err, errHandshakeTranscriptHelloRetryRequestInvalid)
	})
}

func FuzzCanonicalHandshake13(f *testing.F) {
	f.Add(makeRawHandshake13(f, handshake.Header{
		Type:           handshake.TypeClientHello,
		Length:         2,
		FragmentLength: 2,
	}, []byte{0x01, 0x02}))
	f.Add([]byte{byte(handshake.TypeClientHello), 0x00, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		canonical, err := canonicalHandshake13(data)
		if err != nil {
			return
		}
		if !assert.GreaterOrEqual(t, len(canonical), tlsHandshakeHeaderLength13) {
			return
		}
		assert.Equal(t, len(canonical)-tlsHandshakeHeaderLength13, int(util.BigEndianUint24(canonical[1:])))
		assert.Equal(t, data[0], canonical[0])
		assert.Equal(t, data[handshake.HeaderLength:], canonical[tlsHandshakeHeaderLength13:])
	})
}

func makeRawHandshake13(tb testing.TB, header handshake.Header, body []byte) []byte {
	tb.Helper()

	rawHeader, err := header.Marshal()
	assert.NoError(tb, err)

	return append(rawHeader, body...)
}

func canonicalTranscriptHandshake13(typ handshake.Type, body []byte) []byte {
	out := make([]byte, tlsHandshakeHeaderLength13+len(body))
	out[0] = byte(typ)
	util.PutBigEndianUint24(out[1:], uint32(len(body))) //nolint:gosec // G115
	copy(out[tlsHandshakeHeaderLength13:], body)

	return out
}

func hashTranscript13(messages ...[]byte) []byte {
	hash := sha256.New()
	for _, message := range messages {
		_, _ = hash.Write(message)
	}

	return hash.Sum(nil)
}

func pskClientHelloTranscript13(tb testing.TB, binder []byte) ([]byte, []byte) {
	tb.Helper()

	msg := &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		CipherSuiteIDs:     []uint16{0x1301},
		CompressionMethods: []*protocol.CompressionMethod{{}},
		Extensions: []extension.Extension{
			&extension.PreSharedKey{
				Identities: []extension.PskIdentity{
					{
						Identity:            []byte("psk-identity"),
						ObfuscatedTicketAge: 0x01020304,
					},
				},
				Binders: []extension.PskBinderEntry{binder},
			},
		},
	}

	body, err := msg.Marshal()
	assert.NoError(tb, err)

	full := canonicalTranscriptHandshake13(handshake.TypeClientHello, body)
	truncatedLen := len(full) - (2 + 1 + len(binder))
	assert.Greater(tb, truncatedLen, tlsHandshakeHeaderLength13)

	return full, append([]byte(nil), full[:truncatedLen]...)
}

func hmacSHA25613(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)

	return mac.Sum(nil)
}
