// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlscrypto "github.com/pion/dtls/v3/internal/handshakecrypto"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/internal/util"
	dtlshash "github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	canonical, err := canonicalHandshake(raw)
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
			err:  dtlserrors.ErrBufferTooSmall,
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
			err: dtlserrors.ErrInvalidHandshakeTranscriptMessage,
		},
		{
			name: "fragment length",
			raw: makeRawHandshake13(t, handshake.Header{
				Type:            handshake.TypeClientHello,
				Length:          bodyLen,
				MessageSequence: 1,
				FragmentLength:  bodyLen - 1,
			}, body),
			err: dtlserrors.ErrInvalidHandshakeTranscriptMessage,
		},
		{
			name: "body length",
			raw: makeRawHandshake13(t, handshake.Header{
				Type:            handshake.TypeClientHello,
				Length:          bodyLen + 1,
				MessageSequence: 1,
				FragmentLength:  bodyLen + 1,
			}, body),
			err: dtlserrors.ErrInvalidHandshakeTranscriptMessage,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := canonicalHandshake(test.raw)
			assert.ErrorIs(t, err, test.err)
		})
	}
}

func TestHandshakeTranscript13DeferredHashSelection(t *testing.T) {
	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01, 0x02})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x03, 0x04})
	expectedClientHello := append([]byte(nil), clientHello...)

	transcript := NewTranscript()
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, clientHello))
	clientHello[len(clientHello)-1] = 0xff
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer}, serverHello))

	assert.NoError(t, transcript.selectHash(sha256.New))

	sum, err := transcript.sum()
	assert.NoError(t, err)
	assert.Equal(t, hashTranscript13(expectedClientHello, serverHello), sum)
}

func TestHandshakeTranscript13RejectsSumBeforeHashSelection(t *testing.T) {
	transcript := NewTranscript()

	_, err := transcript.sum()
	assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptHashNotSelected)
}

func TestHandshakeTranscript13RejectsHashReselection(t *testing.T) {
	transcript := NewTranscript()
	assert.NoError(t, transcript.selectHash(sha256.New))

	err := transcript.selectHash(sha256.New)
	assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptHashAlreadySelected)
}

func TestHandshakeTranscript13DuplicateHandling(t *testing.T) {
	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	changedClientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x02})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x03})

	transcript := NewTranscript()
	assert.NoError(t, transcript.selectHash(sha256.New))
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, clientHello))
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, clientHello))

	err := transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, changedClientHello)
	assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptMessageChanged)

	assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer}, serverHello))

	sum, err := transcript.sum()
	assert.NoError(t, err)
	assert.Equal(t, hashTranscript13(clientHello, serverHello), sum)
}

func TestAppendVerifiedInboundHandshake13DuplicateHandling(t *testing.T) {
	cipherSuite := ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil)
	rawClientHello := rawHandshakeMessage13(t, 0, transcriptClientHelloMessage13([]byte{0x01}))
	changedClientHello := rawHandshakeMessage13(t, 0, transcriptClientHelloMessage13([]byte{0x02}))

	transcript := NewTranscript()
	require.NoError(t, transcript.AppendVerifiedInbound(true, cipherSuite, rawClientHello))
	beforeBytes := transcript.Bytes()
	beforePending := transcript.pendingMessages()

	require.NoError(t, transcript.AppendVerifiedInbound(true, cipherSuite, rawClientHello))
	assert.Equal(t, beforeBytes, transcript.Bytes())
	assert.Equal(t, beforePending, transcript.pendingMessages())
	assert.Len(t, transcript.messageOrder(), 1)

	err := transcript.AppendVerifiedInbound(true, cipherSuite, changedClientHello)
	assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptMessageChanged)
	assert.Equal(t, beforeBytes, transcript.Bytes())
	assert.Equal(t, beforePending, transcript.pendingMessages())
	assert.Len(t, transcript.messageOrder(), 1)
}

func TestAppendVerifiedInboundHandshakeCacheItems13RequiresExplicitAuthentication(t *testing.T) {
	transcript := NewTranscript()
	rawFinished := rawHandshakeMessage13(t, 0, &handshake.MessageFinished{VerifyData: []byte{0x01}})

	err := AppendVerifiedInboundHandshakeCacheItems(transcript, nil, []*dtlsflight.HandshakeCacheItem{
		{
			Typ:             handshake.TypeFinished,
			MessageSequence: 0,
			Data:            rawFinished,
		},
	})
	assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptExplicitAuthenticationRequired)
	assert.Empty(t, transcript.Bytes())
	assert.Empty(t, transcript.pendingMessages())
	assert.Empty(t, transcript.messageOrder())
}

func TestHandshakeTranscript13RejectsInvalidCanonicalMessage(t *testing.T) {
	transcript := NewTranscript()

	err := transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, []byte{
		byte(handshake.TypeClientHello), 0x00, 0x00, 0x02, 0x01,
	})
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidHandshakeTranscriptMessage)
}

func TestHandshakeTranscript13HelloRetryRequest(t *testing.T) {
	clientHello1 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	helloRetryRequest := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	clientHello2 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x03})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x04})

	transcript := NewTranscript()
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, clientHello1))
	assert.NoError(t, transcript.selectHash(sha256.New))
	assert.NoError(t, transcript.applyHelloRetryRequest())
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer}, helloRetryRequest))
	assert.NoError(
		t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient, Seq: 1}, clientHello2),
	)
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer, Seq: 1}, serverHello))

	clientHello1Hash := hashTranscript13(clientHello1)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	expected := hashTranscript13(messageHash, helloRetryRequest, clientHello2, serverHello)

	sum, err := transcript.sum()
	assert.NoError(t, err)
	assert.Equal(t, expected, sum)
	assert.Equal(t, "MessageHash", handshake.TypeMessageHash.String())
}

func TestAppendVerifiedInboundHandshake13HelloRetryRequest(t *testing.T) {
	cipherSuite := ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil)
	rawClientHello := rawHandshakeMessage13(t, 0, transcriptClientHelloMessage13([]byte{0x01}))
	rawHelloRetryRequest := rawHelloRetryRequest13(t, cipherSuite, 0)
	clientHello, err := canonicalHandshake(rawClientHello)
	require.NoError(t, err)
	helloRetryRequest, err := canonicalHandshake(rawHelloRetryRequest)
	require.NoError(t, err)

	transcript := NewTranscript()
	require.NoError(t, transcript.AppendVerifiedInbound(true, cipherSuite, rawClientHello))
	require.NoError(t, transcript.AppendVerifiedInbound(false, cipherSuite, rawHelloRetryRequest))

	clientHelloHash := hashTranscript13(clientHello)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHelloHash)
	expectedTranscript := append(append([]byte(nil), messageHash...), helloRetryRequest...)
	assert.Equal(t, expectedTranscript, transcript.Bytes())

	sum, err := transcript.SnapshotHash()
	require.NoError(t, err)
	assert.Equal(t, hashTranscript13(messageHash, helloRetryRequest), sum)
	require.Len(t, transcript.messageOrder(), 2)
	assert.Equal(t, handshake.TypeClientHello, transcript.messageOrder()[0].Type)
	assert.Equal(t, handshake.TypeServerHello, transcript.messageOrder()[1].Type)
}

func TestHandshakeTranscript13HelloRetryRequestBinderFork(t *testing.T) {
	clientHello1 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	helloRetryRequest := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	placeholderBinder := make([]byte, sha256.Size)
	_, truncatedClientHello2 := pskClientHelloTranscript13(t, placeholderBinder)

	transcript := NewTranscript()
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, clientHello1))
	assert.NoError(t, transcript.selectHash(sha256.New))
	assert.NoError(t, transcript.applyHelloRetryRequest())
	assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer}, helloRetryRequest))

	mainSumBefore, err := transcript.sum()
	assert.NoError(t, err)
	assert.ErrorIs(t, validateCanonicalHandshake(truncatedClientHello2), dtlserrors.ErrInvalidHandshakeTranscriptMessage)

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
	assert.NoError(
		t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient, Seq: 1}, clientHello2),
	)

	sum, err := transcript.sum()
	assert.NoError(t, err)
	assert.Equal(t, hashTranscript13(messageHash, helloRetryRequest, clientHello2), sum)
}

func TestHandshakeTranscript13HelloRetryRequestErrors(t *testing.T) {
	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})

	t.Run("hash not selected", func(t *testing.T) {
		transcript := NewTranscript()
		assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, clientHello))

		err := transcript.applyHelloRetryRequest()
		assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptHashNotSelected)
	})

	t.Run("not first client hello only", func(t *testing.T) {
		transcript := NewTranscript()
		assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, clientHello))
		assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer}, serverHello))
		assert.NoError(t, transcript.selectHash(sha256.New))

		err := transcript.applyHelloRetryRequest()
		assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid)
	})

	t.Run("server message", func(t *testing.T) {
		transcript := NewTranscript()
		assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer}, serverHello))
		assert.NoError(t, transcript.selectHash(sha256.New))

		err := transcript.applyHelloRetryRequest()
		assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid)
	})

	t.Run("already applied", func(t *testing.T) {
		transcript := NewTranscript()
		assert.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, clientHello))
		assert.NoError(t, transcript.selectHash(sha256.New))
		assert.NoError(t, transcript.applyHelloRetryRequest())

		err := transcript.applyHelloRetryRequest()
		assert.ErrorIs(t, err, dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid)
	})
}

func TestDeriveHandshakeTrafficSecrets13NoHRRAndHRR(t *testing.T) {
	preMasterSecret := bytes.Repeat([]byte{0x42}, sha256.Size)

	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	noHRRTranscriptHash := hashTranscript13(clientHello, serverHello)

	noHRRSecrets, err := deriveHandshakeTrafficSecrets(sha256.New, preMasterSecret, noHRRTranscriptHash)
	require.NoError(t, err)
	require.Len(t, noHRRSecrets.Client, sha256.Size)
	require.Len(t, noHRRSecrets.Server, sha256.Size)
	assert.NotEqual(t, noHRRSecrets.Client, noHRRSecrets.Server)

	again, err := deriveHandshakeTrafficSecrets(sha256.New, preMasterSecret, noHRRTranscriptHash)
	require.NoError(t, err)
	assert.Equal(t, noHRRSecrets, again)

	clientHello1 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x03})
	helloRetryRequest := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x04})
	clientHello2 := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x05})
	serverHello2 := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x06})
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, hashTranscript13(clientHello1))
	hrrTranscriptHash := hashTranscript13(messageHash, helloRetryRequest, clientHello2, serverHello2)

	hrrSecrets, err := deriveHandshakeTrafficSecrets(sha256.New, preMasterSecret, hrrTranscriptHash)
	require.NoError(t, err)
	assert.NotEqual(t, noHRRSecrets.Client, hrrSecrets.Client)
	assert.NotEqual(t, noHRRSecrets.Server, hrrSecrets.Server)

	changedSecret := append([]byte(nil), preMasterSecret...)
	changedSecret[0] ^= 0xff
	changedSecrets, err := deriveHandshakeTrafficSecrets(sha256.New, changedSecret, noHRRTranscriptHash)
	require.NoError(t, err)
	assert.NotEqual(t, noHRRSecrets.Client, changedSecrets.Client)
	assert.NotEqual(t, noHRRSecrets.Server, changedSecrets.Server)
}

func TestDeriveAndStoreHandshakeTrafficSecrets13FromTranscript(t *testing.T) {
	cipherSuite := ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil)
	state := &dtlsstate.State{
		CipherSuite:     cipherSuite,
		PreMasterSecret: bytes.Repeat([]byte{0x11}, sha256.Size),
	}

	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	transcript := NewTranscript()
	require.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, clientHello))
	require.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer}, serverHello))

	require.NoError(t, DeriveAndStoreHandshakeTrafficSecrets(state, transcript))

	transcriptHash, err := transcript.sum()
	require.NoError(t, err)
	expected, err := deriveHandshakeTrafficSecrets(cipherSuite.HashFunc(), state.PreMasterSecret, transcriptHash)
	require.NoError(t, err)
	assert.Equal(t, expected, state.HandshakeTrafficSecrets13)
	assert.NotEmpty(t, state.HandshakeTrafficSecrets13.Client)
	assert.NotEmpty(t, state.HandshakeTrafficSecrets13.Server)
}

func TestInitHandshakeRecordProtection13(t *testing.T) {
	cipherSuite := ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil)
	secretLen := cipherSuite.HashFunc()().Size()
	state := &dtlsstate.State{
		CipherSuite: cipherSuite,
		IsClient:    true,
		HandshakeTrafficSecrets13: dtlsstate.HandshakeTrafficSecrets13{
			Client: bytes.Repeat([]byte{0x11}, secretLen),
			Server: bytes.Repeat([]byte{0x22}, secretLen),
		},
	}

	require.False(t, state.CipherSuite.IsInitialized())
	require.NoError(t, InitHandshakeRecordProtection(state))
	assert.True(t, state.CipherSuite.IsInitialized())
	require.NoError(t, InitHandshakeRecordProtection(state))
}

func TestInitHandshakeRecordProtection13RejectsInvalidState(t *testing.T) {
	tests := []struct {
		name  string
		state *dtlsstate.State
		err   error
	}{
		{
			name: "nil state",
			err:  dtlserrors.ErrCipherSuiteNotSet,
		},
		{
			name:  "missing cipher suite",
			state: &dtlsstate.State{},
			err:   dtlserrors.ErrCipherSuiteNotSet,
		},
		{
			name: "not tls 13",
			state: &dtlsstate.State{
				CipherSuite: ciphersuite.ForID(ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, nil),
				HandshakeTrafficSecrets13: dtlsstate.HandshakeTrafficSecrets13{
					Client: []byte{0x11},
					Server: []byte{0x22},
				},
			},
			err: dtlserrors.ErrInvalidCipherSuite,
		},
		{
			name: "missing client secret",
			state: &dtlsstate.State{
				CipherSuite: ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil),
				HandshakeTrafficSecrets13: dtlsstate.HandshakeTrafficSecrets13{
					Server: []byte{0x22},
				},
			},
			err: dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented,
		},
		{
			name: "missing server secret",
			state: &dtlsstate.State{
				CipherSuite: ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil),
				HandshakeTrafficSecrets13: dtlsstate.HandshakeTrafficSecrets13{
					Client: []byte{0x11},
				},
			},
			err: dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := InitHandshakeRecordProtection(test.state)
			require.ErrorIs(t, err, test.err)
		})
	}
}

func TestCertificateVerifyInput13ServerAndClient(t *testing.T) {
	transcriptHash := bytes.Repeat([]byte{0xa5}, sha256.Size)

	serverInput := certificateVerifyInput(false, transcriptHash)
	clientInput := certificateVerifyInput(true, transcriptHash)

	require.Len(t, serverInput, certificateVerifyPaddingLen13+len(serverCertificateVerifyContext13)+sha256.Size)
	assert.Equal(t, bytes.Repeat([]byte{0x20}, certificateVerifyPaddingLen13),
		serverInput[:certificateVerifyPaddingLen13])
	serverContextEnd := certificateVerifyPaddingLen13 + len(serverCertificateVerifyContext13)
	serverContext := serverInput[certificateVerifyPaddingLen13:serverContextEnd]
	assert.Equal(t, serverCertificateVerifyContext13,
		string(serverContext))
	assert.Equal(t, transcriptHash, serverInput[len(serverInput)-sha256.Size:])

	require.Len(t, clientInput, certificateVerifyPaddingLen13+len(clientCertificateVerifyContext13)+sha256.Size)
	clientContextEnd := certificateVerifyPaddingLen13 + len(clientCertificateVerifyContext13)
	clientContext := clientInput[certificateVerifyPaddingLen13:clientContextEnd]
	assert.Equal(t, clientCertificateVerifyContext13,
		string(clientContext))
	assert.Equal(t, transcriptHash, clientInput[len(clientInput)-sha256.Size:])
	assert.NotEqual(t, serverInput, clientInput)
}

func TestFinishedVerifyData13(t *testing.T) {
	baseKey := bytes.Repeat([]byte{0x11}, sha256.Size)
	transcriptHash := bytes.Repeat([]byte{0x22}, sha256.Size)

	finishedKey, err := finishedKey(sha256.New, baseKey)
	require.NoError(t, err)

	verifyData, err := finishedVerifyData(sha256.New, baseKey, transcriptHash)
	require.NoError(t, err)
	require.Len(t, verifyData, sha256.Size)

	expectedMAC := hmac.New(sha256.New, finishedKey)
	_, err = expectedMAC.Write(transcriptHash)
	require.NoError(t, err)
	assert.Equal(t, expectedMAC.Sum(nil), verifyData)
	assert.NoError(t, verifyFinishedData(sha256.New, baseKey, transcriptHash, verifyData))

	changedTranscript := append([]byte(nil), transcriptHash...)
	changedTranscript[0] ^= 0xff
	changedVerifyData, err := finishedVerifyData(sha256.New, baseKey, changedTranscript)
	require.NoError(t, err)
	assert.NotEqual(t, verifyData, changedVerifyData)

	changedKey := append([]byte(nil), baseKey...)
	changedKey[0] ^= 0xff
	changedKeyVerifyData, err := finishedVerifyData(sha256.New, changedKey, transcriptHash)
	require.NoError(t, err)
	assert.NotEqual(t, verifyData, changedKeyVerifyData)

	badVerifyData := append([]byte(nil), verifyData...)
	badVerifyData[0] ^= 0xff
	assert.ErrorIs(t, verifyFinishedData(sha256.New, baseKey, transcriptHash, badVerifyData),
		dtlserrors.ErrVerifyDataMismatch)
}

func TestCertificateVerifyFailureDoesNotPoisonTranscript13(t *testing.T) {
	cipherSuite := ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil)
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	signer, ok := cert.PrivateKey.(crypto.Signer)
	require.True(t, ok)

	transcript := NewTranscript()
	require.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient},
		canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})))
	require.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer},
		canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})))
	require.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer, Seq: 1},
		canonicalTranscriptHandshake13(handshake.TypeCertificate, []byte{0x03})))
	require.NoError(t, selectHashIfReady(transcript, cipherSuite))

	beforeBytes := transcript.Bytes()
	beforeHash, err := transcript.SnapshotHash()
	require.NoError(t, err)

	verifyInput, err := CertificateVerifyInputFromTranscript(false, transcript)
	require.NoError(t, err)
	certVerifySignature, err := dtlscrypto.GenerateCertificateVerify(
		verifyInput,
		signer,
		dtlshash.SHA256,
		signature.ECDSA,
	)
	require.NoError(t, err)

	badSignature := append([]byte(nil), certVerifySignature...)
	badSignature[len(badSignature)-1] ^= 0xff
	err = dtlscrypto.VerifyCertificateVerify(
		verifyInput,
		dtlshash.SHA256,
		signature.ECDSA,
		badSignature,
		cert.Certificate,
	)
	require.ErrorIs(t, err, dtlserrors.ErrKeySignatureMismatch)

	afterHash, err := transcript.SnapshotHash()
	require.NoError(t, err)
	assert.Equal(t, beforeBytes, transcript.Bytes())
	assert.Equal(t, beforeHash, afterHash)

	require.NoError(t, dtlscrypto.VerifyCertificateVerify(
		verifyInput,
		dtlshash.SHA256,
		signature.ECDSA,
		certVerifySignature,
		cert.Certificate,
	))
	rawCertificateVerify := rawHandshakeMessage13(t, 2, &handshake.MessageCertificateVerify{
		HashAlgorithm:      dtlshash.SHA256,
		SignatureAlgorithm: signature.ECDSA,
		Signature:          certVerifySignature,
	})
	require.NoError(t, transcript.AppendVerifiedInbound(false, cipherSuite, rawCertificateVerify))
	certificateVerify, err := canonicalHandshake(rawCertificateVerify)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte(nil), beforeBytes...), certificateVerify...), transcript.Bytes())
}

func TestFinishedFailureDoesNotPoisonTranscript13(t *testing.T) {
	cipherSuite := ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil)
	baseKey := bytes.Repeat([]byte{0x44}, sha256.Size)

	transcript := NewTranscript()
	require.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient},
		canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})))
	require.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer},
		canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})))
	require.NoError(t, selectHashIfReady(transcript, cipherSuite))

	beforeBytes := transcript.Bytes()
	beforeHash, err := transcript.SnapshotHash()
	require.NoError(t, err)

	verifyData, err := FinishedVerifyDataFromTranscript(sha256.New, baseKey, transcript)
	require.NoError(t, err)
	badVerifyData := append([]byte(nil), verifyData...)
	badVerifyData[0] ^= 0xff

	err = VerifyFinishedDataFromTranscript(sha256.New, baseKey, transcript, badVerifyData)
	require.ErrorIs(t, err, dtlserrors.ErrVerifyDataMismatch)

	afterHash, err := transcript.SnapshotHash()
	require.NoError(t, err)
	assert.Equal(t, beforeBytes, transcript.Bytes())
	assert.Equal(t, beforeHash, afterHash)

	require.NoError(t, VerifyFinishedDataFromTranscript(sha256.New, baseKey, transcript, verifyData))
	rawFinished := rawHandshakeMessage13(t, 2, &handshake.MessageFinished{VerifyData: verifyData})
	require.NoError(t, transcript.AppendVerifiedInbound(false, cipherSuite, rawFinished))
	finished, err := canonicalHandshake(rawFinished)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte(nil), beforeBytes...), finished...), transcript.Bytes())
}

func TestDTLS13TranscriptAuthenticatedHandshakeInputs(t *testing.T) {
	cipherSuite := ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil)
	state := &dtlsstate.State{
		CipherSuite:     cipherSuite,
		PreMasterSecret: bytes.Repeat([]byte{0x77}, sha256.Size),
	}
	transcript := NewTranscript()

	clientHello := canonicalTranscriptHandshake13(handshake.TypeClientHello, []byte{0x01})
	serverHello := canonicalTranscriptHandshake13(handshake.TypeServerHello, []byte{0x02})
	require.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderClient}, clientHello))
	require.NoError(t, transcript.appendCanonical(transcriptMessageID{sender: transcriptSenderServer}, serverHello))

	require.NoError(t, DeriveAndStoreHandshakeTrafficSecrets(state, transcript))
	require.NotEmpty(t, state.HandshakeTrafficSecrets13.Client)
	require.NotEmpty(t, state.HandshakeTrafficSecrets13.Server)

	certificate := canonicalTranscriptHandshake13(handshake.TypeCertificate, []byte{0x03})
	require.NoError(t, transcript.appendCanonical(transcriptMessageID{
		sender: transcriptSenderServer,
		Seq:    1,
	}, certificate))

	certVerifyInput, err := certificateVerifyInputFromTranscript(false, transcript)
	require.NoError(t, err)
	certVerifyTranscriptHash, err := transcript.sum()
	require.NoError(t, err)
	assert.Equal(t, certVerifyTranscriptHash, certVerifyInput[len(certVerifyInput)-sha256.Size:])

	certVerify := canonicalTranscriptHandshake13(handshake.TypeCertificateVerify, []byte{0x04})
	require.NoError(t, transcript.appendCanonical(transcriptMessageID{
		sender: transcriptSenderServer,
		Seq:    2,
	}, certVerify))

	verifyData, err := finishedVerifyDataFromTranscript(
		sha256.New,
		state.HandshakeTrafficSecrets13.Server,
		transcript,
	)
	require.NoError(t, err)
	finishedTranscriptHash, err := transcript.sum()
	require.NoError(t, err)
	assert.NoError(t, verifyFinishedData(
		sha256.New,
		state.HandshakeTrafficSecrets13.Server,
		finishedTranscriptHash,
		verifyData,
	))
}

func FuzzCanonicalHandshake13(f *testing.F) {
	f.Add(makeRawHandshake13(f, handshake.Header{
		Type:           handshake.TypeClientHello,
		Length:         2,
		FragmentLength: 2,
	}, []byte{0x01, 0x02}))
	f.Add([]byte{byte(handshake.TypeClientHello), 0x00, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, data []byte) {
		canonical, err := canonicalHandshake(data)
		if err != nil {
			return
		}
		if !assert.GreaterOrEqual(t, len(canonical), tlsHandshakeHeaderLength) {
			return
		}
		assert.Equal(t, len(canonical)-tlsHandshakeHeaderLength, int(util.BigEndianUint24(canonical[1:])))
		assert.Equal(t, data[0], canonical[0])
		assert.Equal(t, data[handshake.HeaderLength:], canonical[tlsHandshakeHeaderLength:])
	})
}

func makeRawHandshake13(tb testing.TB, header handshake.Header, body []byte) []byte {
	tb.Helper()

	rawHeader, err := header.Marshal()
	assert.NoError(tb, err)

	return append(rawHeader, body...)
}

func rawHandshakeMessage13(tb testing.TB, seq uint16, message handshake.Message) []byte {
	tb.Helper()

	body, err := message.Marshal()
	require.NoError(tb, err)

	return makeRawHandshake13(tb, handshake.Header{
		Type:            message.Type(),
		Length:          uint32(len(body)), //nolint:gosec // G115
		MessageSequence: seq,
		FragmentLength:  uint32(len(body)), //nolint:gosec // G115
	}, body)
}

func transcriptClientHelloMessage13(sessionID []byte) *handshake.MessageClientHello {
	return &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		SessionID:          sessionID,
		CipherSuiteIDs:     []uint16{uint16(ciphersuite.TLS_AES_128_GCM_SHA256)},
		CompressionMethods: []*protocol.CompressionMethod{{}},
	}
}

func rawHelloRetryRequest13(
	tb testing.TB,
	cipherSuite ciphersuite.CipherSuite,
	seq uint16,
) []byte {
	tb.Helper()

	random := handshake.Random{}
	random.UnmarshalFixed([32]byte(handshake.HelloRetryRequestRandom()))
	cipherSuiteID := uint16(cipherSuite.ID())

	return rawHandshakeMessage13(tb, seq, &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            random,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: &protocol.CompressionMethod{},
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions:        []protocol.Version{protocol.Version1_3},
				SelectedVersion: true,
			},
		},
	})
}

func canonicalTranscriptHandshake13(typ handshake.Type, body []byte) []byte {
	out := make([]byte, tlsHandshakeHeaderLength+len(body))
	out[0] = byte(typ)
	util.PutBigEndianUint24(out[1:], uint32(len(body))) //nolint:gosec // G115
	copy(out[tlsHandshakeHeaderLength:], body)

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
	assert.Greater(tb, truncatedLen, tlsHandshakeHeaderLength)

	return full, append([]byte(nil), full[:truncatedLen]...)
}

func hmacSHA25613(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)

	return mac.Sum(nil)
}
