// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"crypto/hmac"
	"hash"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlscrypto "github.com/pion/dtls/v3/internal/handshakecrypto"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

const (
	clientHandshakeTrafficLabel   = "c hs traffic"
	serverHandshakeTrafficLabel   = "s hs traffic"
	clientApplicationTrafficLabel = "c ap traffic"
	serverApplicationTrafficLabel = "s ap traffic"
	exporterMasterSecretLabel     = "exp master"
	resumptionMasterSecretLabel   = "res master"
	trafficUpdateLabel            = "traffic upd"
	derivedSecretLabel            = "derived"
	finishedLabel                 = "finished"

	serverCertificateVerifyContext = "TLS 1.3, server CertificateVerify\x00"
	clientCertificateVerifyContext = "TLS 1.3, client CertificateVerify\x00"
	certificateVerifyPaddingLen    = 64
)

type handshakeKeySchedule struct {
	HandshakeTrafficSecrets dtlsstate.TrafficSecrets
	MasterSecret            []byte
}

func commitPreparedFlights(conn Conn, state *dtlsstate.State13, transcript *Transcript, cfg *dtlsconfig.HandshakeConfig, flights []*dtlsflight.Outbound) error {
	nextEpoch, protectedFlightStart := prepareFlightPackets(state, cfg.InitialEpoch, flights)
	if err := commitOutboundFlight(state, transcript, flights, protectedFlightStart); err != nil {
		return err
	}
	if nextEpoch == cfg.InitialEpoch {
		return nil
	}

	cfg.Log.Tracef("[handshake13:%s] -> changeCipherSpec (epoch: %d)", sideString(state.IsClient), nextEpoch)
	conn.SetLocalEpoch(nextEpoch)

	return nil
}

func prepareFlightPackets(
	state *dtlsstate.State13,
	epoch uint16,
	flights []*dtlsflight.Outbound,
) (uint16, int) {
	nextEpoch := epoch
	protectedFlightStart := len(flights)
	for i, packet := range flights {
		packet.Epoch += epoch
		if packet.Epoch > nextEpoch {
			nextEpoch = packet.Epoch
		}
		if packet.Protection == dtlsflight.ProtectionCiphertext && protectedFlightStart == len(flights) {
			protectedFlightStart = i
		}
		if handshakeMessage, ok := packet.Content.(*handshake.Handshake); ok {
			handshakeMessage.Header.MessageSequence = uint16(state.HandshakeSendSequence) //nolint:gosec // G115
			state.HandshakeSendSequence++
		}
	}

	return nextEpoch, protectedFlightStart
}

func commitOutboundFlight(state *dtlsstate.State13, transcript *Transcript, flights []*dtlsflight.Outbound, protectedFlightStart int) error {
	if err := appendCommittedOutboundHandshakeFlight(state, transcript, flights[:protectedFlightStart]); err != nil {
		return err
	}
	if protectedFlightStart == len(flights) {
		return nil
	}
	if err := ensureHandshakeTrafficSecrets(state, transcript); err != nil {
		return err
	}
	if err := InitHandshakeRecordProtection(state); err != nil {
		return err
	}

	return appendCommittedOutboundHandshakeFlight(state, transcript, flights[protectedFlightStart:])
}

func ensureHandshakeTrafficSecrets(state *dtlsstate.State13, transcript *Transcript) error {
	secrets := state.KeySchedule.HandshakeTraffic
	if len(secrets.Client) == 0 && len(secrets.Server) == 0 {
		return DeriveAndStoreHandshakeTrafficSecrets(state, transcript)
	}

	return selectHashIfReady(transcript, state.CipherSuite)
}

func appendCommittedOutboundHandshakeFlight(state *dtlsstate.State13, transcript *Transcript, pkts []*dtlsflight.Outbound) error {
	for _, p := range pkts {
		if err := populateOutboundCertificateVerify(state, transcript, p); err != nil {
			return err
		}
		if err := populateOutboundFinished(state, transcript, p); err != nil {
			return err
		}
		if err := AppendOutboundHandshakeFlight(transcript, state.IsClient, state.CipherSuite, []*dtlsflight.Outbound{p}); err != nil {
			return err
		}
	}

	return nil
}

func populateOutboundCertificateVerify(state *dtlsstate.State13, transcript *Transcript, pkt *dtlsflight.Outbound) error {
	if pkt == nil || pkt.Content == nil {
		return nil
	}
	h, ok := pkt.Content.(*handshake.Handshake)
	if !ok {
		return nil
	}
	certificateVerify, ok := h.Message.(*handshake.MessageCertificateVerify)
	if !ok || len(certificateVerify.Signature) != 0 {
		return nil
	}
	if pkt.CertificateVerifySigner == nil {
		return dtlserrors.ErrInvalidPrivateKey
	}

	input, err := CertificateVerifyInputFromTranscript(state.IsClient, transcript)
	if err != nil {
		return err
	}
	certificateVerify.Signature, err = dtlscrypto.GenerateCertificateVerify(input, pkt.CertificateVerifySigner, certificateVerify.HashAlgorithm, certificateVerify.SignatureAlgorithm)

	return err
}

func populateOutboundFinished(
	state *dtlsstate.State13,
	transcript *Transcript,
	p *dtlsflight.Outbound,
) error {
	if p == nil || p.Content == nil {
		return nil
	}
	h, ok := p.Content.(*handshake.Handshake)
	if !ok {
		return nil
	}
	finished, ok := h.Message.(*handshake.MessageFinished)
	if !ok || len(finished.VerifyData) != 0 {
		return nil
	}
	if state.CipherSuite == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}

	baseKey, err := ServerHandshakeFinishedBaseKey(state)
	if state.IsClient {
		baseKey, err = ClientHandshakeFinishedBaseKey(state)
	}
	if err != nil {
		return err
	}

	verifyData, err := FinishedVerifyDataFromTranscript(state.CipherSuite.HashFunc(), baseKey, transcript)
	if err != nil {
		return err
	}
	finished.VerifyData = verifyData

	return nil
}

// deriveHandshakeTrafficSecrets derives the DTLS 1.3 client and server
// handshake traffic secrets from the ECDHE secret and transcript hash.
func deriveHandshakeTrafficSecrets(hashFunc func() hash.Hash, keyAgreementSecret, transcriptHash []byte) (dtlsstate.TrafficSecrets, error) {
	secrets, err := deriveHandshakeKeySchedule(hashFunc, keyAgreementSecret, transcriptHash)
	if err != nil {
		return dtlsstate.TrafficSecrets{}, err
	}

	return secrets.HandshakeTrafficSecrets, nil
}

func deriveHandshakeKeySchedule(hashFunc func() hash.Hash, keyAgreementSecret, transcriptHash []byte) (handshakeKeySchedule, error) {
	hashSize, err := hashSize(hashFunc)
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

	return handshakeKeySchedule{HandshakeTrafficSecrets: dtlsstate.TrafficSecrets{Client: clientSecret, Server: serverSecret}, MasterSecret: masterSecret}, nil
}

func deriveHandshakeSecret(hashFunc func() hash.Hash, keyAgreementSecret []byte) ([]byte, error) {
	hashSize, err := hashSize(hashFunc)
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
	hashSize, err := hashSize(hashFunc)
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

func deriveTrafficSecret(hashFunc func() hash.Hash, baseSecret []byte, label string, transcriptHash []byte) ([]byte, error) {
	hashSize, err := hashSize(hashFunc)
	if err != nil {
		return nil, err
	}
	if len(baseSecret) != hashSize || len(transcriptHash) != hashSize {
		return nil, dtlserrors.ErrLengthMismatch
	}

	return keyschedule.HkdfExpandLabel(hashFunc, baseSecret, label, transcriptHash, hashSize)
}

func deriveApplicationTrafficSecrets(hashFunc func() hash.Hash, masterSecret, transcriptHash []byte) (dtlsstate.TrafficSecrets, error) {
	clientSecret, err := deriveTrafficSecret(
		hashFunc,
		masterSecret,
		clientApplicationTrafficLabel,
		transcriptHash,
	)
	if err != nil {
		return dtlsstate.TrafficSecrets{}, err
	}

	serverSecret, err := deriveTrafficSecret(
		hashFunc,
		masterSecret,
		serverApplicationTrafficLabel,
		transcriptHash,
	)
	if err != nil {
		return dtlsstate.TrafficSecrets{}, err
	}

	return dtlsstate.TrafficSecrets{
		Client: clientSecret,
		Server: serverSecret,
	}, nil
}

// deriveNextApplicationTrafficSecret derives the next generation of a
// DTLS 1.3 application traffic secret as defined by RFC 8446 section 7.2.
// The next-generation application_traffic_secret is computed as:
// application_traffic_secret_N+1 =
// HKDF-Expand-Label(application_traffic_secret_N,
//
//	"traffic upd", "", Hash.length)
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-7.2
func deriveNextApplicationTrafficSecret(
	hashFunc func() hash.Hash,
	current []byte,
) ([]byte, error) {
	hashSize, err := hashSize(hashFunc)
	if err != nil {
		return nil, err
	}
	if len(current) != hashSize {
		return nil, dtlserrors.ErrLengthMismatch
	}

	return keyschedule.HkdfExpandLabel(hashFunc, current, trafficUpdateLabel, nil, hashSize)
}

func deriveMasterSecretFromKeyAgreementSecret(hashFunc func() hash.Hash, keyAgreementSecret []byte) ([]byte, error) {
	handshakeSecret, err := deriveHandshakeSecret(hashFunc, keyAgreementSecret)
	if err != nil {
		return nil, err
	}

	return deriveMasterSecret(hashFunc, handshakeSecret)
}

func deriveExporterMasterSecret(hashFunc func() hash.Hash, masterSecret, transcriptHash []byte) ([]byte, error) {
	return deriveTrafficSecret(hashFunc, masterSecret, exporterMasterSecretLabel, transcriptHash)
}

func deriveResumptionMasterSecret(hashFunc func() hash.Hash, masterSecret, transcriptHash []byte) ([]byte, error) {
	return deriveTrafficSecret(hashFunc, masterSecret, resumptionMasterSecretLabel, transcriptHash)
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

// DeriveAndStoreApplicationTrafficSecrets derives DTLS 1.3 application
// traffic and exporter master secrets from the current transcript snapshot.
// The caller is responsible for invoking it with the transcript through server
// Finished.
func DeriveAndStoreApplicationTrafficSecrets(state *dtlsstate.State13, transcript *Transcript) error {
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

	masterSecret, err := ensureMasterSecret(state)
	if err != nil {
		return err
	}

	secrets, err := deriveApplicationTrafficSecrets(
		state.CipherSuite.HashFunc(),
		masterSecret,
		transcriptHash,
	)
	if err != nil {
		return err
	}

	exporterMasterSecret, err := deriveExporterMasterSecret(
		state.CipherSuite.HashFunc(),
		masterSecret,
		transcriptHash,
	)
	if err != nil {
		return err
	}

	state.KeySchedule.ClientApplicationTrafficSecret0 = secrets.Client
	state.KeySchedule.ServerApplicationTrafficSecret0 = secrets.Server
	state.KeySchedule.ExporterMasterSecret = exporterMasterSecret

	return nil
}

// DeriveAndStoreResumptionMasterSecret derives the DTLS 1.3 resumption master
// secret from the current transcript snapshot. The caller is responsible for
// invoking it with the transcript through client Finished.
func DeriveAndStoreResumptionMasterSecret(state *dtlsstate.State13, transcript *Transcript) error {
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

	masterSecret, err := ensureMasterSecret(state)
	if err != nil {
		return err
	}

	state.KeySchedule.ResumptionMasterSecret, err = deriveResumptionMasterSecret(state.CipherSuite.HashFunc(), masterSecret, transcriptHash)

	return err
}

func ensureMasterSecret(state *dtlsstate.State13) ([]byte, error) {
	hashSize, err := hashSize(state.CipherSuite.HashFunc())
	if err != nil {
		return nil, err
	}
	if len(state.KeySchedule.MasterSecret) != 0 {
		if len(state.KeySchedule.MasterSecret) != hashSize {
			return nil, dtlserrors.ErrLengthMismatch
		}

		return state.KeySchedule.MasterSecret, nil
	}

	masterSecret, err := deriveMasterSecretFromKeyAgreementSecret(
		state.CipherSuite.HashFunc(),
		state.KeyAgreementSecret,
	)
	if err != nil {
		return nil, err
	}
	state.KeySchedule.MasterSecret = masterSecret

	return masterSecret, nil
}

// ClientHandshakeFinishedBaseKey returns the client handshake traffic secret,
// which is the TLS 1.3 Finished base key for the client's Finished message.
func ClientHandshakeFinishedBaseKey(state *dtlsstate.State13) ([]byte, error) {
	if state == nil {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}
	if len(state.KeySchedule.HandshakeTraffic.Client) == 0 {
		return nil, dtlserrors.ErrLengthMismatch
	}

	return state.KeySchedule.HandshakeTraffic.Client, nil
}

// ServerHandshakeFinishedBaseKey returns the server handshake traffic secret,
// which is the TLS 1.3 Finished base key for the server's Finished message.
func ServerHandshakeFinishedBaseKey(state *dtlsstate.State13) ([]byte, error) {
	if state == nil {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}
	if len(state.KeySchedule.HandshakeTraffic.Server) == 0 {
		return nil, dtlserrors.ErrLengthMismatch
	}

	return state.KeySchedule.HandshakeTraffic.Server, nil
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

// certificateVerifyInput returns the TLS 1.3 CertificateVerify input for a
// transcript hash.
func certificateVerifyInput(isClient bool, transcriptHash []byte) []byte {
	context := serverCertificateVerifyContext
	if isClient {
		context = clientCertificateVerifyContext
	}

	out := make([]byte, certificateVerifyPaddingLen, certificateVerifyPaddingLen+len(context)+len(transcriptHash))
	for i := range out {
		out[i] = 0x20
	}
	out = append(out, context...)
	out = append(out, transcriptHash...)

	return out
}

// finishedKey returns the TLS 1.3 finished key derived from baseKey.
func finishedKey(hashFunc func() hash.Hash, baseKey []byte) ([]byte, error) {
	hashSize, err := hashSize(hashFunc)
	if err != nil {
		return nil, err
	}

	return keyschedule.HkdfExpandLabel(hashFunc, baseKey, finishedLabel, nil, hashSize)
}

// FinishedVerifyDataFromTranscript returns verify_data for the current
// transcript snapshot.
func FinishedVerifyDataFromTranscript(hashFunc func() hash.Hash, baseKey []byte, transcript *Transcript) ([]byte, error) {
	if transcript == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	transcriptHash, err := transcript.SnapshotHash()
	if err != nil {
		return nil, err
	}

	return finishedVerifyData(hashFunc, baseKey, transcriptHash)
}

// finishedVerifyData returns TLS 1.3 Finished verify_data.
func finishedVerifyData(hashFunc func() hash.Hash, baseKey, transcriptHash []byte) ([]byte, error) {
	hashSize, err := hashSize(hashFunc)
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
// against the current transcript snapshot.
func VerifyFinishedDataFromTranscript(hashFunc func() hash.Hash, baseKey []byte, transcript *Transcript, verifyData []byte) error {
	if transcript == nil {
		return dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}

	transcriptHash, err := transcript.SnapshotHash()
	if err != nil {
		return err
	}

	return verifyFinishedData(hashFunc, baseKey, transcriptHash, verifyData)
}

func hashSize(hashFunc func() hash.Hash) (int, error) {
	if hashFunc == nil {
		return 0, dtlserrors.ErrKeyScheduleMissingHashFunction
	}
	h := hashFunc()
	if h == nil {
		return 0, dtlserrors.ErrKeyScheduleMissingHashFunction
	}

	return h.Size(), nil
}
