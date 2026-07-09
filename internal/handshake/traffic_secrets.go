// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"crypto/hmac"
	"hash"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/keyschedule"
)

const (
	clientHandshakeTrafficLabel = "c hs traffic"
	serverHandshakeTrafficLabel = "s hs traffic"
	derivedSecretLabel          = "derived"
	finishedLabel               = "finished"

	serverCertificateVerifyContext13 = "TLS 1.3, server CertificateVerify\x00"
	clientCertificateVerifyContext13 = "TLS 1.3, client CertificateVerify\x00"
	certificateVerifyPaddingLen13    = 64
)

type handshakeKeySchedule struct {
	HandshakeTrafficSecrets dtlsstate.TrafficSecrets
	MasterSecret            []byte
}

// deriveHandshakeTrafficSecrets derives the DTLS 1.3 client and server
// handshake traffic secrets from the ECDHE secret and transcript hash.
func deriveHandshakeTrafficSecrets(
	hashFunc func() hash.Hash,
	keyAgreementSecret, transcriptHash []byte,
) (dtlsstate.HandshakeTrafficSecrets, error) {
	secrets, err := deriveHandshakeKeySchedule(hashFunc, keyAgreementSecret, transcriptHash)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets{}, err
	}

	return secrets.HandshakeTrafficSecrets, nil
}

func deriveHandshakeKeySchedule(
	hashFunc func() hash.Hash,
	keyAgreementSecret, transcriptHash []byte,
) (handshakeKeySchedule, error) {
	hashSize, err := hashSize13(hashFunc)
	if err != nil {
		return handshakeKeySchedule{}, err
	}
	if len(keyAgreementSecret) == 0 || len(transcriptHash) != hashSize {
		return handshakeKeySchedule{}, dtlserrors.ErrLengthMismatch
	}

	handshakeSecret, err := deriveHandshakeSecret(hashFunc, keyAgreementSecret)
	if err != nil {
		return handshakeKeySchedule{}, err
	}

	clientSecret, err := deriveTrafficSecret(
		hashFunc,
		handshakeSecret,
		clientHandshakeTrafficLabel,
		transcriptHash,
	)
	if err != nil {
		return handshakeKeySchedule{}, err
	}

	serverSecret, err := deriveTrafficSecret(
		hashFunc,
		handshakeSecret,
		serverHandshakeTrafficLabel,
		transcriptHash,
	)
	if err != nil {
		return handshakeKeySchedule{}, err
	}

	masterSecret, err := deriveMasterSecret(hashFunc, handshakeSecret)
	if err != nil {
		return handshakeKeySchedule{}, err
	}

	return handshakeKeySchedule{
		HandshakeTrafficSecrets: dtlsstate.TrafficSecrets{
			Client: clientSecret,
			Server: serverSecret,
		},
		MasterSecret: masterSecret,
	}, nil
}

func deriveHandshakeSecret(hashFunc func() hash.Hash, keyAgreementSecret []byte) ([]byte, error) {
	hashSize, err := hashSize13(hashFunc)
	if err != nil {
		return nil, err
	}
	if len(keyAgreementSecret) == 0 {
		return nil, dtlserrors.ErrLengthMismatch
	}

	zeroSecret := make([]byte, hashSize)
	earlySecret, err := keyschedule.HkdfExtract(hashFunc, nil, zeroSecret)
	if err != nil {
		return nil, err
	}

	derivedSecret, err := keyschedule.DeriveSecret(hashFunc, earlySecret, derivedSecretLabel, nil)
	if err != nil {
		return nil, err
	}

	return keyschedule.HkdfExtract(hashFunc, derivedSecret, keyAgreementSecret)
}

func deriveMasterSecret(hashFunc func() hash.Hash, handshakeSecret []byte) ([]byte, error) {
	hashSize, err := hashSize13(hashFunc)
	if err != nil {
		return nil, err
	}
	if len(handshakeSecret) != hashSize {
		return nil, dtlserrors.ErrLengthMismatch
	}

	derivedSecret, err := keyschedule.DeriveSecret(hashFunc, handshakeSecret, derivedSecretLabel, nil)
	if err != nil {
		return nil, err
	}

	return keyschedule.HkdfExtract(hashFunc, derivedSecret, make([]byte, hashSize))
}

func deriveTrafficSecret(
	hashFunc func() hash.Hash,
	baseSecret []byte,
	label string,
	transcriptHash []byte,
) ([]byte, error) {
	hashSize, err := hashSize13(hashFunc)
	if err != nil {
		return nil, err
	}
	if len(baseSecret) != hashSize || len(transcriptHash) != hashSize {
		return nil, dtlserrors.ErrLengthMismatch
	}

	return keyschedule.HkdfExpandLabel(hashFunc, baseSecret, label, transcriptHash, hashSize)
}

// DeriveAndStoreHandshakeTrafficSecrets derives DTLS 1.3 handshake traffic
// secrets and stores them in state.
func DeriveAndStoreHandshakeTrafficSecrets(state *dtlsstate.State13, transcript *Transcript) error {
	if state == nil || state.CipherSuite == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}
	if transcript == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if err := selectHashIfReady(transcript, state.CipherSuite); err != nil {
		return err
	}

	transcriptHash, err := transcript.SnapshotHash()
	if err != nil {
		return err
	}

	secrets, err := deriveHandshakeKeySchedule(
		state.CipherSuite.HashFunc(),
		state.KeyAgreementSecret,
		transcriptHash,
	)
	if err != nil {
		return err
	}
	state.KeySchedule.HandshakeTraffic = secrets.HandshakeTrafficSecrets
	state.KeySchedule.MasterSecret = secrets.MasterSecret

	return nil
}

// CertificateVerifyInputFromTranscript returns the TLS 1.3 CertificateVerify
// input for the current transcript snapshot.
func CertificateVerifyInputFromTranscript(
	isClient bool,
	transcript *Transcript,
) ([]byte, error) {
	if transcript == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	transcriptHash, err := transcript.SnapshotHash()
	if err != nil {
		return nil, err
	}

	return certificateVerifyInput(isClient, transcriptHash), nil
}

// certificateVerifyInputFromTranscript returns the TLS 1.3 CertificateVerify
// input for the current transcript hash.
func certificateVerifyInputFromTranscript(
	isClient bool,
	transcript *Transcript,
) ([]byte, error) {
	return CertificateVerifyInputFromTranscript(isClient, transcript)
}

// certificateVerifyInput returns the TLS 1.3 CertificateVerify input for a
// transcript hash.
func certificateVerifyInput(isClient bool, transcriptHash []byte) []byte {
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

// finishedKey returns the TLS 1.3 finished key derived from baseKey.
func finishedKey(hashFunc func() hash.Hash, baseKey []byte) ([]byte, error) {
	hashSize, err := hashSize13(hashFunc)
	if err != nil {
		return nil, err
	}

	return keyschedule.HkdfExpandLabel(hashFunc, baseKey, finishedLabel, nil, hashSize)
}

// FinishedVerifyDataFromTranscript returns verify_data for the current
// transcript snapshot.
func FinishedVerifyDataFromTranscript(
	hashFunc func() hash.Hash,
	baseKey []byte,
	transcript *Transcript,
) ([]byte, error) {
	if transcript == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	transcriptHash, err := transcript.SnapshotHash()
	if err != nil {
		return nil, err
	}

	return finishedVerifyData(hashFunc, baseKey, transcriptHash)
}

// finishedVerifyDataFromTranscript returns verify_data for the current
// transcript hash.
func finishedVerifyDataFromTranscript(
	hashFunc func() hash.Hash,
	baseKey []byte,
	transcript *Transcript,
) ([]byte, error) {
	return FinishedVerifyDataFromTranscript(hashFunc, baseKey, transcript)
}

// finishedVerifyData returns TLS 1.3 Finished verify_data.
func finishedVerifyData(hashFunc func() hash.Hash, baseKey, transcriptHash []byte) ([]byte, error) {
	hashSize, err := hashSize13(hashFunc)
	if err != nil {
		return nil, err
	}
	if len(transcriptHash) != hashSize {
		return nil, dtlserrors.ErrLengthMismatch
	}

	finishedKey, err := finishedKey(hashFunc, baseKey)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(hashFunc, finishedKey)
	if _, err := mac.Write(transcriptHash); err != nil {
		return nil, err
	}

	return mac.Sum(nil), nil
}

// verifyFinishedData verifies TLS 1.3 Finished verify_data.
func verifyFinishedData(hashFunc func() hash.Hash, baseKey, transcriptHash, verifyData []byte) error {
	expected, err := finishedVerifyData(hashFunc, baseKey, transcriptHash)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, verifyData) {
		return dtlserrors.ErrVerifyDataMismatch
	}

	return nil
}

// VerifyFinishedDataFromTranscript verifies TLS 1.3 Finished verify_data
// against the current transcript snapshot. It does not commit the Finished
// message to the transcript.
func VerifyFinishedDataFromTranscript(
	hashFunc func() hash.Hash,
	baseKey []byte,
	transcript *Transcript,
	verifyData []byte,
) error {
	if transcript == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	transcriptHash, err := transcript.SnapshotHash()
	if err != nil {
		return err
	}

	return verifyFinishedData(hashFunc, baseKey, transcriptHash, verifyData)
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
