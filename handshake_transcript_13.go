// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

const tlsHandshakeHeaderLength13 = 4

const (
	clientHandshakeTrafficLabel13 = "c hs traffic"
	serverHandshakeTrafficLabel13 = "s hs traffic"
	derivedSecretLabel13          = "derived"
	finishedLabel13               = "finished"

	serverCertificateVerifyContext13 = "TLS 1.3, server CertificateVerify\x00"
	clientCertificateVerifyContext13 = "TLS 1.3, client CertificateVerify\x00"
	certificateVerifyPaddingLen13    = 64
)

type transcriptSender13 uint8

const (
	transcriptClient13 transcriptSender13 = iota
	transcriptServer13
)

type transcriptMessageID13 struct {
	sender transcriptSender13
	seq    uint16
}

type seenTranscriptMessage13 struct {
	length      int
	fingerprint [sha256.Size]byte
}

type transcriptMessage13 struct {
	id  transcriptMessageID13
	typ handshake.Type
}

type handshakeTranscript13 struct {
	newHash func() hash.Hash
	h       hash.Hash

	pending    [][]byte
	transcript []byte
	seen       map[transcriptMessageID13]seenTranscriptMessage13
	order      []transcriptMessage13

	helloRetryApplied bool
}

func newHandshakeTranscript13() *handshakeTranscript13 {
	return &handshakeTranscript13{
		seen: make(map[transcriptMessageID13]seenTranscriptMessage13),
	}
}

func canonicalHandshake13(raw []byte) ([]byte, error) {
	if len(raw) < handshake.HeaderLength {
		return nil, dtlserrors.ErrBufferTooSmall
	}

	var header handshake.Header
	if err := header.Unmarshal(raw); err != nil {
		return nil, err
	}

	if header.FragmentOffset != 0 ||
		header.FragmentLength != header.Length ||
		len(raw) != handshake.HeaderLength+int(header.Length) {
		return nil, dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	out := make([]byte, tlsHandshakeHeaderLength13+int(header.Length))
	copy(out[:tlsHandshakeHeaderLength13], raw[:tlsHandshakeHeaderLength13])
	copy(out[tlsHandshakeHeaderLength13:], raw[handshake.HeaderLength:])

	return out, nil
}

func (t *handshakeTranscript13) selectHash(newHash func() hash.Hash) error {
	if newHash == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if t.h != nil {
		return dtlserrors.ErrHandshakeTranscriptHashAlreadySelected
	}

	h := newHash()
	if h == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	for _, message := range t.pending {
		if _, err := h.Write(message); err != nil {
			return err
		}
	}
	t.newHash = newHash
	t.h = h
	t.pending = nil

	return nil
}

func (t *handshakeTranscript13) appendCanonical(id transcriptMessageID13, message []byte) error {
	if err := validateCanonicalHandshake13(message); err != nil {
		return err
	}

	fingerprint := sha256.Sum256(message)
	if seen, ok := t.seen[id]; ok {
		if seen.length == len(message) && seen.fingerprint == fingerprint {
			return nil
		}

		return dtlserrors.ErrHandshakeTranscriptMessageChanged
	}

	messageCopy := append([]byte(nil), message...)
	t.seen[id] = seenTranscriptMessage13{
		length:      len(messageCopy),
		fingerprint: fingerprint,
	}
	t.order = append(t.order, transcriptMessage13{
		id:  id,
		typ: handshake.Type(messageCopy[0]),
	})
	t.transcript = append(t.transcript, messageCopy...)

	if t.h == nil {
		t.pending = append(t.pending, messageCopy)

		return nil
	}

	_, err := t.h.Write(messageCopy)

	return err
}

func (t *handshakeTranscript13) sum() ([]byte, error) {
	if t.h == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	return t.h.Sum(nil), nil
}

func (t *handshakeTranscript13) sumWithSuffix(suffix []byte) ([]byte, error) {
	if t.h == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	h := t.newHash()
	if h == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if _, err := h.Write(t.transcript); err != nil {
		return nil, err
	}
	if _, err := h.Write(suffix); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func (t *handshakeTranscript13) hasInitialClientHello() bool {
	return len(t.order) == 1 &&
		t.order[0].id.sender == transcriptClient13 &&
		t.order[0].typ == handshake.TypeClientHello
}

func (t *handshakeTranscript13) applyHelloRetryRequest() error {
	if t.h == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if t.helloRetryApplied || !t.hasInitialClientHello() {
		return dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid
	}

	clientHelloDigest := t.h.Sum(nil)
	messageHash := make([]byte, tlsHandshakeHeaderLength13+len(clientHelloDigest))
	messageHash[0] = byte(handshake.TypeMessageHash)
	util.PutBigEndianUint24(messageHash[1:], uint32(len(clientHelloDigest))) //nolint:gosec // G115
	copy(messageHash[tlsHandshakeHeaderLength13:], clientHelloDigest)

	h := t.newHash()
	if h == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if _, err := h.Write(messageHash); err != nil {
		return err
	}
	t.h = h
	t.transcript = append(t.transcript[:0], messageHash...)
	t.helloRetryApplied = true

	return nil
}

func validateCanonicalHandshake13(message []byte) error {
	if len(message) < tlsHandshakeHeaderLength13 {
		return dtlserrors.ErrBufferTooSmall
	}
	if int(util.BigEndianUint24(message[1:])) != len(message)-tlsHandshakeHeaderLength13 {
		return dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	return nil
}

func deriveHandshakeTrafficSecrets13(
	hashFunc func() hash.Hash,
	preMasterSecret, transcriptHash []byte,
) (dtlsstate.HandshakeTrafficSecrets13, error) {
	hashSize, err := hashSize13(hashFunc)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets13{}, err
	}
	if len(preMasterSecret) == 0 || len(transcriptHash) != hashSize {
		return dtlsstate.HandshakeTrafficSecrets13{}, dtlserrors.ErrLengthMismatch
	}

	zeroSecret := make([]byte, hashSize)
	earlySecret, err := keyschedule.HkdfExtract(hashFunc, nil, zeroSecret)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets13{}, err
	}

	derivedSecret, err := keyschedule.DeriveSecret(hashFunc, earlySecret, derivedSecretLabel13, nil)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets13{}, err
	}

	handshakeSecret, err := keyschedule.HkdfExtract(hashFunc, derivedSecret, preMasterSecret)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets13{}, err
	}

	clientSecret, err := keyschedule.HkdfExpandLabel(
		hashFunc,
		handshakeSecret,
		clientHandshakeTrafficLabel13,
		transcriptHash,
		hashSize,
	)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets13{}, err
	}

	serverSecret, err := keyschedule.HkdfExpandLabel(
		hashFunc,
		handshakeSecret,
		serverHandshakeTrafficLabel13,
		transcriptHash,
		hashSize,
	)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets13{}, err
	}

	return dtlsstate.HandshakeTrafficSecrets13{
		Client: clientSecret,
		Server: serverSecret,
	}, nil
}

func deriveAndStoreHandshakeTrafficSecrets13(state *dtlsstate.State, transcript *handshakeTranscript13) error {
	if state == nil || state.CipherSuite == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}
	if transcript == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if err := selectTranscriptHashIfReady13(transcript, state.CipherSuite); err != nil {
		return err
	}

	transcriptHash, err := transcript.sum()
	if err != nil {
		return err
	}

	secrets, err := deriveHandshakeTrafficSecrets13(
		state.CipherSuite.HashFunc(),
		state.PreMasterSecret,
		transcriptHash,
	)
	if err != nil {
		return err
	}
	state.HandshakeTrafficSecrets13 = secrets

	return nil
}

func certificateVerifyInputFromTranscript13(
	isClient bool,
	transcript *handshakeTranscript13,
) ([]byte, error) {
	if transcript == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	transcriptHash, err := transcript.sum()
	if err != nil {
		return nil, err
	}

	return certificateVerifyInput13(isClient, transcriptHash), nil
}

func certificateVerifyInput13(isClient bool, transcriptHash []byte) []byte {
	context := serverCertificateVerifyContext13
	if isClient {
		context = clientCertificateVerifyContext13
	}

	out := make([]byte, certificateVerifyPaddingLen13, certificateVerifyPaddingLen13+len(context)+len(transcriptHash))
	for i := range out {
		out[i] = 0x20
	}
	out = append(out, context...)
	out = append(out, transcriptHash...)

	return out
}

func finishedKey13(hashFunc func() hash.Hash, baseKey []byte) ([]byte, error) {
	hashSize, err := hashSize13(hashFunc)
	if err != nil {
		return nil, err
	}

	return keyschedule.HkdfExpandLabel(hashFunc, baseKey, finishedLabel13, nil, hashSize)
}

func finishedVerifyDataFromTranscript13(
	hashFunc func() hash.Hash,
	baseKey []byte,
	transcript *handshakeTranscript13,
) ([]byte, error) {
	if transcript == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	transcriptHash, err := transcript.sum()
	if err != nil {
		return nil, err
	}

	return finishedVerifyData13(hashFunc, baseKey, transcriptHash)
}

func finishedVerifyData13(hashFunc func() hash.Hash, baseKey, transcriptHash []byte) ([]byte, error) {
	hashSize, err := hashSize13(hashFunc)
	if err != nil {
		return nil, err
	}
	if len(transcriptHash) != hashSize {
		return nil, dtlserrors.ErrLengthMismatch
	}

	finishedKey, err := finishedKey13(hashFunc, baseKey)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(hashFunc, finishedKey)
	if _, err := mac.Write(transcriptHash); err != nil {
		return nil, err
	}

	return mac.Sum(nil), nil
}

func verifyFinishedData13(hashFunc func() hash.Hash, baseKey, transcriptHash, verifyData []byte) error {
	expected, err := finishedVerifyData13(hashFunc, baseKey, transcriptHash)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, verifyData) {
		return dtlserrors.ErrVerifyDataMismatch
	}

	return nil
}

func hashSize13(hashFunc func() hash.Hash) (int, error) {
	if hashFunc == nil {
		return 0, dtlserrors.ErrKeyScheduleMissingHashFunction
	}
	h := hashFunc()
	if h == nil {
		return 0, dtlserrors.ErrKeyScheduleMissingHashFunction
	}

	return h.Size(), nil
}
