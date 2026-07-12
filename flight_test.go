// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"hash"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlshandshake "github.com/pion/dtls/v3/internal/handshake"
	dtlscrypto "github.com/pion/dtls/v3/internal/handshakecrypto"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	dtlshash "github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tlsHandshakeHeaderLength13 = 4

var (
	//nolint:gochecknoglobals
	testCurves13                            = []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384}
	errFlight13ConnectionCallbackRejected   = errors.New("connection callback rejected")
	errFlight13ServerIdentityCallbackReject = errors.New("identity callback rejected")
)

type Flight = dtlsflight13.Flight

const (
	Flight0 = dtlsflight13.Flight0
	Flight1 = dtlsflight13.Flight1
	Flight2 = dtlsflight13.Flight2
	Flight3 = dtlsflight13.Flight3
	Flight4 = dtlsflight13.Flight4
	Flight5 = dtlsflight13.Flight5
)

type handshakeTestContext13 struct {
	state      *dtlsstate.State13
	cache      *dtlsflight.Cache
	cfg        *dtlsconfig.HandshakeConfig
	transcript *dtlshandshake.Transcript
}

func newTestState13(isClient bool) *dtlsstate.State13 {
	state := dtlsstate.NewState13(isClient)

	return &state
}

func flight13ParseForTest(
	testingT require.TestingT,
	flight Flight,
	ctx context.Context,
	flightCtx *handshakeTestContext13,
) (Flight, *alert.Alert, error) {
	return flight13ParseForTestWithConn(testingT, flight, ctx, nil, flightCtx)
}

func flight13ParseForTestWithConn(
	testingT require.TestingT,
	flight Flight,
	ctx context.Context,
	conn dtlsflight.Conn,
	flightCtx *handshakeTestContext13,
) (Flight, *alert.Alert, error) {
	if helper, ok := testingT.(interface{ Helper() }); ok {
		helper.Helper()
	}

	nextFlight, dtlsAlert, err, ok := dtlsflight13.Parse(
		ctx,
		flight,
		conn,
		flightCtx.state,
		flightCtx.cache,
		flightCtx.cfg,
		func(cipherSuite dtlsconfig.CipherSuite, items []*dtlsflight.HandshakeCacheItem) error {
			return dtlshandshake.AppendVerifiedInboundHandshakeCacheItems(flightCtx.transcript, cipherSuite, items)
		},
		func(cipherSuite dtlsconfig.CipherSuite, items []*dtlsflight.HandshakeCacheItem) error {
			return dtlshandshake.VerifyAndAppendProtectedHandshakeCacheItems13(
				flightCtx.transcript,
				flightCtx.state,
				flightCtx.cfg,
				cipherSuite,
				items,
			)
		},
		func(state *dtlsstate.State13) error {
			return dtlshandshake.DeriveAndStoreHandshakeTrafficSecrets(state, flightCtx.transcript)
		},
		dtlshandshake.InitHandshakeRecordProtection,
	)
	require.True(testingT, ok)

	return nextFlight, dtlsAlert, err
}

type flight13QueuedPacketConn struct {
	handleQueuedPackets func(context.Context) error
}

func (c *flight13QueuedPacketConn) HandleQueuedPackets(ctx context.Context) error {
	if c.handleQueuedPackets == nil {
		return nil
	}

	return c.handleQueuedPackets(ctx)
}

func (c *flight13QueuedPacketConn) SessionKey() []byte {
	return nil
}

func flight13GenerateForTest(
	testingT require.TestingT,
	flight Flight,
	flightCtx *handshakeTestContext13,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	if helper, ok := testingT.(interface{ Helper() }); ok {
		helper.Helper()
	}

	gen, _, ok := dtlsflight13.GetGenerator(flight)
	require.True(testingT, ok)

	return gen(nil, flightCtx.state, flightCtx.cache, flightCtx.cfg)
}

func canonicalPacketHandshake13(t *testing.T, p *dtlsflight.Packet) []byte {
	t.Helper()

	content, ok := p.Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := content.Marshal()
	require.NoError(t, err)
	canonical, err := canonicalHandshake13(raw)
	require.NoError(t, err)

	return canonical
}

func canonicalTranscriptHandshake13(typ handshake.Type, body []byte) []byte {
	out := make([]byte, tlsHandshakeHeaderLength13+len(body))
	out[0] = byte(typ)
	util.PutBigEndianUint24(out[1:], uint32(len(body))) //nolint:gosec // G115
	copy(out[tlsHandshakeHeaderLength13:], body)

	return out
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

func hashTranscript13(messages ...[]byte) []byte {
	hash := sha256.New()
	for _, message := range messages {
		_, _ = hash.Write(message)
	}

	return hash.Sum(nil)
}

func deriveHandshakeTrafficSecrets13(
	hashFunc func() hash.Hash,
	keyAgreementSecret, transcriptHash []byte,
) (dtlsstate.TrafficSecrets, error) {
	hashSize := hashFunc().Size()
	zeroSecret := make([]byte, hashSize)
	earlySecret, err := keyschedule.HkdfExtract(hashFunc, nil, zeroSecret)
	if err != nil {
		return dtlsstate.TrafficSecrets{}, err
	}

	derivedSecret, err := keyschedule.DeriveSecret(hashFunc, earlySecret, "derived", nil)
	if err != nil {
		return dtlsstate.TrafficSecrets{}, err
	}

	handshakeSecret, err := keyschedule.HkdfExtract(hashFunc, derivedSecret, keyAgreementSecret)
	if err != nil {
		return dtlsstate.TrafficSecrets{}, err
	}

	clientSecret, err := keyschedule.HkdfExpandLabel(hashFunc, handshakeSecret, "c hs traffic", transcriptHash, hashSize)
	if err != nil {
		return dtlsstate.TrafficSecrets{}, err
	}
	serverSecret, err := keyschedule.HkdfExpandLabel(hashFunc, handshakeSecret, "s hs traffic", transcriptHash, hashSize)
	if err != nil {
		return dtlsstate.TrafficSecrets{}, err
	}

	return dtlsstate.TrafficSecrets{Client: clientSecret, Server: serverSecret}, nil
}

func finishedVerifyData13(
	t *testing.T,
	hashFunc func() hash.Hash,
	baseKey, transcriptHash []byte,
) []byte {
	t.Helper()

	finishedKey, err := keyschedule.HkdfExpandLabel(hashFunc, baseKey, "finished", nil, hashFunc().Size())
	require.NoError(t, err)

	mac := hmac.New(hashFunc, finishedKey)
	_, err = mac.Write(transcriptHash)
	require.NoError(t, err)

	return mac.Sum(nil)
}

func marshalFinished13(t *testing.T, seq uint16, verifyData []byte) []byte {
	t.Helper()

	raw, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: seq},
		Message: &handshake.MessageFinished{VerifyData: verifyData},
	}).Marshal()
	require.NoError(t, err)

	return raw
}

func marshalServerFinished13(
	t *testing.T,
	state *dtlsstate.State13,
	seq uint16,
	transcriptMessages ...[]byte,
) []byte {
	t.Helper()

	verifyData := finishedVerifyData13(
		t,
		state.CipherSuite.HashFunc(),
		state.KeySchedule.HandshakeTraffic.Server,
		hashTranscript13(transcriptMessages...),
	)

	return marshalFinished13(t, seq, verifyData)
}

type flight13ProtectedServerFlightFixture struct {
	cfg                          *dtlsconfig.HandshakeConfig
	state                        *dtlsstate.State13
	transcript                   *dtlshandshake.Transcript
	clientHelloCanonical         []byte
	serverHelloCanonical         []byte
	encryptedExtensionsCanonical []byte
	rawServerHello               []byte
	rawEncryptedExtensions       []byte
	rawFinished                  []byte
	handshakeSecrets             dtlsstate.TrafficSecrets
}

func newFlight13ProtectedServerFlightFixture(t *testing.T) flight13ProtectedServerFlightFixture {
	t.Helper()

	cfg := testHandshakeConfig13(t)
	state := newTestState13(true)
	transcript := dtlshandshake.NewTranscript()
	clientHello, _, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{state: state, cfg: cfg})
	require.NoError(t, err)
	appended, err := dtlshandshake.AppendClientHelloInitialFlights(transcript, clientHello)
	require.NoError(t, err)
	require.True(t, appended)
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello[0])

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)
	rawServerHello := marshalServerHello(t, cfg, handshake.Random{
		RandomBytes: [handshake.RandomBytesLength]byte{0x01},
	}, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})
	serverHelloCanonical, err := canonicalHandshake13(rawServerHello)
	require.NoError(t, err)

	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	encryptedExtensionsCanonical, err := canonicalHandshake13(rawEncryptedExtensions)
	require.NoError(t, err)

	clientKeypair := state.LocalKeypairs[group]
	require.NotNil(t, clientKeypair)
	keyAgreementSecret, err := prf.PreMasterSecret(clientKeypair.PublicKey, serverKeypair.PrivateKey, group)
	require.NoError(t, err)
	handshakeSecrets, err := deriveHandshakeTrafficSecrets13(
		cfg.LocalCipherSuites[0].HashFunc(),
		keyAgreementSecret,
		hashTranscript13(clientHelloCanonical, serverHelloCanonical),
	)
	require.NoError(t, err)
	state.CipherSuite = cfg.LocalCipherSuites[0]
	state.KeySchedule.HandshakeTraffic = handshakeSecrets
	rawFinished := marshalServerFinished13(
		t,
		state,
		2,
		clientHelloCanonical,
		serverHelloCanonical,
		encryptedExtensionsCanonical,
	)
	state.CipherSuite = nil
	state.KeySchedule.HandshakeTraffic = dtlsstate.TrafficSecrets{}

	return flight13ProtectedServerFlightFixture{
		cfg:                          cfg,
		state:                        state,
		transcript:                   transcript,
		clientHelloCanonical:         clientHelloCanonical,
		serverHelloCanonical:         serverHelloCanonical,
		encryptedExtensionsCanonical: encryptedExtensionsCanonical,
		rawServerHello:               rawServerHello,
		rawEncryptedExtensions:       rawEncryptedExtensions,
		rawFinished:                  rawFinished,
		handshakeSecrets:             handshakeSecrets,
	}
}

func (f flight13ProtectedServerFlightFixture) cacheWithFinished(rawFinished []byte) *dtlsflight.Cache {
	cache := dtlsflight.NewCache()
	cache.Push(f.rawServerHello, f.cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	cache.Push(f.rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	cache.Push(rawFinished, dtlsflight13.EpochHandshake, 2, handshake.TypeFinished, false)

	return cache
}

type flight13ProtectedServerCertificateFlight struct {
	cache                      *dtlsflight.Cache
	certificateCanonical       []byte
	certificateVerifyCanonical []byte
	finishedCanonical          []byte
}

func (f flight13ProtectedServerFlightFixture) cacheWithCertificate(
	t *testing.T,
	certificate tls.Certificate,
) flight13ProtectedServerCertificateFlight {
	t.Helper()

	rawCertificate := marshalCertificate13(t, 2, certificate.Certificate)
	certificateCanonical, err := canonicalHandshake13(rawCertificate)
	require.NoError(t, err)

	signer, ok := certificate.PrivateKey.(crypto.Signer)
	require.True(t, ok)
	rawCertificateVerify := marshalServerCertificateVerify13(
		t,
		3,
		signer,
		f.clientHelloCanonical,
		f.serverHelloCanonical,
		f.encryptedExtensionsCanonical,
		certificateCanonical,
	)
	certificateVerifyCanonical, err := canonicalHandshake13(rawCertificateVerify)
	require.NoError(t, err)

	f.state.CipherSuite = f.cfg.LocalCipherSuites[0]
	f.state.KeySchedule.HandshakeTraffic = f.handshakeSecrets
	rawFinished := marshalServerFinished13(
		t,
		f.state,
		4,
		f.clientHelloCanonical,
		f.serverHelloCanonical,
		f.encryptedExtensionsCanonical,
		certificateCanonical,
		certificateVerifyCanonical,
	)
	f.state.CipherSuite = nil
	f.state.KeySchedule.HandshakeTraffic = dtlsstate.TrafficSecrets{}
	finishedCanonical, err := canonicalHandshake13(rawFinished)
	require.NoError(t, err)

	cache := dtlsflight.NewCache()
	cache.Push(f.rawServerHello, f.cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	cache.Push(f.rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	cache.Push(rawCertificate, dtlsflight13.EpochHandshake, 2, handshake.TypeCertificate, false)
	cache.Push(rawCertificateVerify, dtlsflight13.EpochHandshake, 3, handshake.TypeCertificateVerify, false)
	cache.Push(rawFinished, dtlsflight13.EpochHandshake, 4, handshake.TypeFinished, false)

	return flight13ProtectedServerCertificateFlight{
		cache:                      cache,
		certificateCanonical:       certificateCanonical,
		certificateVerifyCanonical: certificateVerifyCanonical,
		finishedCanonical:          finishedCanonical,
	}
}

func marshalCertificate13(t *testing.T, seq uint16, rawCertificates [][]byte) []byte {
	t.Helper()

	entries := make([]handshake.CertificateEntry13, 0, len(rawCertificates))
	for _, rawCertificate := range rawCertificates {
		entries = append(entries, handshake.CertificateEntry13{
			CertificateData: rawCertificate,
		})
	}

	raw, err := (&handshake.Handshake{
		Header: handshake.Header{MessageSequence: seq},
		Message: &handshake.MessageCertificate13{
			CertificateList: entries,
		},
	}).Marshal()
	require.NoError(t, err)

	return raw
}

func marshalServerCertificateVerify13(
	t *testing.T,
	seq uint16,
	signer crypto.Signer,
	transcriptMessages ...[]byte,
) []byte {
	t.Helper()

	signatureBytes, err := dtlscrypto.GenerateCertificateVerify(
		serverCertificateVerifyInput13(t, transcriptMessages...),
		signer,
		dtlshash.SHA256,
		signature.ECDSA,
	)
	require.NoError(t, err)

	raw, err := (&handshake.Handshake{
		Header: handshake.Header{MessageSequence: seq},
		Message: &handshake.MessageCertificateVerify{
			HashAlgorithm:      dtlshash.SHA256,
			SignatureAlgorithm: signature.ECDSA,
			Signature:          signatureBytes,
		},
	}).Marshal()
	require.NoError(t, err)

	return raw
}

func serverCertificateVerifyInput13(t *testing.T, transcriptMessages ...[]byte) []byte {
	t.Helper()

	transcriptHash := hashTranscript13(transcriptMessages...)
	out := make([]byte, 64, 64+len("TLS 1.3, server CertificateVerify\x00")+len(transcriptHash))
	for i := range out {
		out[i] = 0x20
	}
	out = append(out, []byte("TLS 1.3, server CertificateVerify\x00")...)
	out = append(out, transcriptHash...)

	return out
}

func flight13RootCAsForCertificate(t *testing.T, certificate tls.Certificate) *x509.CertPool {
	t.Helper()

	leaf := certificate.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		require.NoError(t, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return pool
}

func testHandshakeConfig13(t *testing.T) *dtlsconfig.HandshakeConfig {
	t.Helper()

	cipherSuite := ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil)
	require.NotNil(t, cipherSuite)

	loggerFactory := logging.NewDefaultLoggerFactory()

	return &dtlsconfig.HandshakeConfig{
		LocalCipherSuites:           []dtlsconfig.CipherSuite{cipherSuite},
		EllipticCurves:              testCurves13,
		InitialRetransmitInterval:   time.Second,
		ExtendedMasterSecret:        dtlsconfig.RequestExtendedMasterSecret,
		Log:                         loggerFactory.NewLogger("dtls"),
		MinVersion:                  protocol.Version1_3,
		MaxVersion:                  protocol.Version1_3,
		LocalSignatureSchemes:       signaturehash.Algorithms13(),
		LocalCertSignatureSchemes:   nil,
		LocalSRTPProtectionProfiles: nil,
	}
}

type rawExtension struct {
	typeValue extension.TypeValue
	raw       []byte
}

func (e rawExtension) Marshal() ([]byte, error) {
	return append([]byte(nil), e.raw...), nil
}

func (e rawExtension) Unmarshal([]byte) error {
	return nil
}

func (e rawExtension) TypeValue() extension.TypeValue {
	return e.typeValue
}

func marshalHelloRetryRequestServerHello(
	t *testing.T,
	cfg *dtlsconfig.HandshakeConfig,
	extensions []extension.Extension,
) []byte {
	t.Helper()

	var hrrRandomFixed [handshake.RandomLength]byte
	copy(hrrRandomFixed[:], handshake.HelloRetryRequestRandom())
	var hrrRandom handshake.Random
	hrrRandom.UnmarshalFixed(hrrRandomFixed)

	return marshalServerHello(t, cfg, hrrRandom, extensions)
}

func marshalServerHello(
	t *testing.T,
	cfg *dtlsconfig.HandshakeConfig,
	random handshake.Random,
	extensions []extension.Extension,
) []byte {
	t.Helper()

	return marshalServerHelloWithSequence(t, cfg, random, extensions, 0)
}

func marshalServerHelloWithSequence(
	t *testing.T,
	cfg *dtlsconfig.HandshakeConfig,
	random handshake.Random,
	extensions []extension.Extension,
	seq uint16,
) []byte {
	t.Helper()

	cipherSuiteID := uint16(cfg.LocalCipherSuites[0].ID())
	serverHello := &handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            random,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
		Extensions:        extensions,
	}
	rawServerHello, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: seq},
		Message: serverHello,
	}).Marshal()
	require.NoError(t, err)

	return rawServerHello
}

func generateFlight13_1ClientHello(t *testing.T, cfg *dtlsconfig.HandshakeConfig) *handshake.MessageClientHello {
	t.Helper()

	state := newTestState13(false)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	return clientHello
}

func TestFlight13_1GenerateClientHelloUsesSupportedVersionsVector(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var supportedVersions *extension.SupportedVersions
	for _, ext := range clientHello.Extensions {
		if sv, ok := ext.(*extension.SupportedVersions); ok {
			supportedVersions = sv

			break
		}
	}
	require.NotNil(t, supportedVersions)
	assert.Equal(t, []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)
	assert.False(t, supportedVersions.IsSelectedVersion())
}

func TestFlight13_1GenerateClientHelloIncludesSignatureAlgorithms(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.LocalCertSignatureSchemes = cfg.LocalSignatureSchemes[:1]

	clientHello := generateFlight13_1ClientHello(t, cfg)

	var signatureAlgorithms *extension.SupportedSignatureAlgorithms
	var signatureAlgorithmsCert *extension.SignatureAlgorithmsCert
	for _, ext := range clientHello.Extensions {
		switch typed := ext.(type) {
		case *extension.SupportedSignatureAlgorithms:
			signatureAlgorithms = typed
		case *extension.SignatureAlgorithmsCert:
			signatureAlgorithmsCert = typed
		}
	}

	require.NotNil(t, signatureAlgorithms)
	assert.Equal(t, cfg.LocalSignatureSchemes, signatureAlgorithms.SignatureHashAlgorithms)
	require.NotNil(t, signatureAlgorithmsCert)
	assert.Equal(t, cfg.LocalCertSignatureSchemes, signatureAlgorithmsCert.SignatureHashAlgorithms)
}

func TestFlight13_1GenerateClientHelloIncludesSupportedGroups(t *testing.T) {
	cfg := testHandshakeConfig13(t)

	clientHello := generateFlight13_1ClientHello(t, cfg)

	var supportedGroups *extension.SupportedEllipticCurves
	for _, ext := range clientHello.Extensions {
		if typed, ok := ext.(*extension.SupportedEllipticCurves); ok {
			supportedGroups = typed

			break
		}
	}

	require.NotNil(t, supportedGroups)
	assert.Equal(t, cfg.EllipticCurves, supportedGroups.EllipticCurves)
}

func TestFlight13_1GenerateRetainsPrivateKeysForAdvertisedShares(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var keyShare *extension.KeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			keyShare = ks

			break
		}
	}
	require.NotNil(t, keyShare)
	require.Len(t, keyShare.ClientShares, len(cfg.EllipticCurves))
	require.Len(t, state.LocalKeyEntries, len(keyShare.ClientShares))
	require.Len(t, state.LocalKeypairs, len(keyShare.ClientShares))

	for _, entry := range keyShare.ClientShares {
		t.Run(entry.Group.String(), func(t *testing.T) {
			localKeypair, ok := state.LocalKeypairs[entry.Group]
			require.True(t, ok)
			require.Equal(t, entry.KeyExchange, localKeypair.PublicKey)

			peerKeypair, err := elliptic.GenerateKeypair(entry.Group)
			require.NoError(t, err)

			localSecret, err := prf.PreMasterSecret(peerKeypair.PublicKey, localKeypair.PrivateKey, entry.Group)
			require.NoError(t, err)

			peerSecret, err := prf.PreMasterSecret(localKeypair.PublicKey, peerKeypair.PrivateKey, entry.Group)
			require.NoError(t, err)

			assert.Equal(t, peerSecret, localSecret)
		})
	}
}

func TestFlight13_1GenerateClientHelloIncludesX25519MLKEM768KeyShare(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768}
	state := newTestState13(false)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var keyShare *extension.KeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			keyShare = ks

			break
		}
	}
	require.NotNil(t, keyShare)
	require.Len(t, keyShare.ClientShares, 1)
	assert.Equal(t, elliptic.X25519MLKEM768, keyShare.ClientShares[0].Group)
	assert.Len(t, keyShare.ClientShares[0].KeyExchange, elliptic.X25519MLKEM768ClientPublicKeySize)

	localKeypair := state.LocalKeypairs[elliptic.X25519MLKEM768]
	require.NotNil(t, localKeypair)
	serverKeypair, err := elliptic.GenerateKeypairForPeer(elliptic.X25519MLKEM768, localKeypair.PublicKey)
	require.NoError(t, err)
	assert.Len(t, serverKeypair.PublicKey, elliptic.X25519MLKEM768ServerPublicKeySize)

	clientSecret, err := prf.PreMasterSecret(
		serverKeypair.PublicKey,
		localKeypair.PrivateKey,
		elliptic.X25519MLKEM768,
	)
	require.NoError(t, err)
	serverSecret, err := prf.PreMasterSecret(
		localKeypair.PublicKey,
		serverKeypair.PrivateKey,
		elliptic.X25519MLKEM768,
	)
	require.NoError(t, err)

	assert.Equal(t, serverSecret, clientSecret)
	assert.Len(t, clientSecret, elliptic.X25519MLKEM768SharedSecretSize)
}

func TestFlight13_1ParseStoresHelloRetryRequestSelectedGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			&extension.SupportedVersions{
				Versions:        []protocol.Version{protocol.Version1_3},
				SelectedVersion: true,
			},
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := newTestState13(false)
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight1, context.Background(), &handshakeTestContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight3, nextFlight)
	entries := *state.RemoteKeyEntries
	require.Len(t, entries, 1)
	assert.Equal(t, selectedGroup, entries[0].Group)
	assert.Empty(t, entries[0].KeyExchange)
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithoutSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := newTestState13(false)
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight1, context.Background(), &handshakeTestContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrInvalidHelloRetryRequest)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.Nil(t, state.RemoteKeyEntries)
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithWrongSelectedVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			&extension.SupportedVersions{
				Versions:        []protocol.Version{protocol.Version1_2},
				SelectedVersion: true,
			},
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := newTestState13(false)
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight1, context.Background(), &handshakeTestContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.ProtocolVersion, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.Nil(t, state.RemoteKeyEntries)
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithClientHelloSupportedVersionsEncoding(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Extension{
			rawExtension{
				typeValue: extension.SupportedVersionsTypeValue,
				raw: []byte{
					0x00, 0x2b, // supported_versions
					0x00, 0x03, // extension_data length
					0x02,       // ClientHello vector length
					0xfe, 0xfc, // DTLS v1.3
				},
			},
			&extension.KeyShare{SelectedGroup: &selectedGroup},
		},
	)

	state := newTestState13(false)
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight1, context.Background(), &handshakeTestContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrInvalidHelloRetryRequest)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.Nil(t, state.RemoteKeyEntries)
}

func TestFlight13_3GenerateRejectsWithoutCommonVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)
	require.NoError(t, state.LocalRandom.Populate())

	pkts, dtlsAlert, err := flight13GenerateForTest(t, Flight3, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrNoCommonProtocolVersion)
	require.Nil(t, dtlsAlert)
	require.Nil(t, pkts)
}

func TestFlight13_3GenerateIncludesCookieAndSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)
	state.Cookie = []byte{0x01, 0x02, 0x03, 0x04}
	state.RemoteVersions = []protocol.Version{protocol.Version1_3}
	require.NoError(t, state.LocalRandom.Populate())

	pkts, dtlsAlert, err := flight13GenerateForTest(t, Flight3, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var supportedVersions *extension.SupportedVersions
	for _, ext := range clientHello.Extensions {
		if sv, ok := ext.(*extension.SupportedVersions); ok {
			supportedVersions = sv

			break
		}
	}
	require.NotNil(t, supportedVersions)
	assert.Equal(t, []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)
	assert.False(t, supportedVersions.IsSelectedVersion())

	var signatureAlgorithms *extension.SupportedSignatureAlgorithms
	for _, ext := range clientHello.Extensions {
		if sigAlgs, ok := ext.(*extension.SupportedSignatureAlgorithms); ok {
			signatureAlgorithms = sigAlgs

			break
		}
	}
	require.NotNil(t, signatureAlgorithms)
	assert.Equal(t, cfg.LocalSignatureSchemes, signatureAlgorithms.SignatureHashAlgorithms)

	var cookieExt *extension.CookieExt
	for _, ext := range clientHello.Extensions {
		if c, ok := ext.(*extension.CookieExt); ok {
			cookieExt = c

			break
		}
	}
	require.NotNil(t, cookieExt)
	assert.Equal(t, state.Cookie, cookieExt.Cookie)
}

func TestFlight13_3GeneratePrioritizesHelloRetryRequestSelectedGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	originalKeypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)
	state := newTestState13(false)
	state.RemoteVersions = []protocol.Version{protocol.Version1_3}
	state.LocalKeyEntries = []extension.KeyShareEntry{
		{Group: originalKeypair.Curve, KeyExchange: originalKeypair.PublicKey},
	}
	state.RemoteKeyEntries = &[]extension.KeyShareEntry{{Group: selectedGroup}}
	require.NoError(t, state.LocalRandom.Populate())

	pkts, dtlsAlert, err := flight13GenerateForTest(t, Flight3, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var keyShare *extension.KeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			keyShare = ks

			break
		}
	}
	require.NotNil(t, keyShare)
	require.Len(t, keyShare.ClientShares, 2)
	assert.Equal(t, selectedGroup, keyShare.ClientShares[0].Group)
	assert.NotEmpty(t, keyShare.ClientShares[0].KeyExchange)
	assert.Equal(t, elliptic.X25519, keyShare.ClientShares[1].Group)

	selectedKeypair := state.LocalKeypairs[selectedGroup]
	require.NotNil(t, selectedKeypair)
	assert.Equal(t, keyShare.ClientShares[0].KeyExchange, selectedKeypair.PublicKey)
}

func TestFlight13_3GenerateDoesNotRegenerateAlreadyAdvertisedGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.X25519

	keypair, err := elliptic.GenerateKeypair(selectedGroup)
	require.NoError(t, err)
	state := newTestState13(false)
	state.RemoteVersions = []protocol.Version{protocol.Version1_3}
	state.LocalKeyEntries = []extension.KeyShareEntry{
		{Group: keypair.Curve, KeyExchange: keypair.PublicKey},
	}
	state.RemoteKeyEntries = &[]extension.KeyShareEntry{{Group: selectedGroup}}
	require.NoError(t, state.LocalRandom.Populate())

	pkts, dtlsAlert, err := flight13GenerateForTest(t, Flight3, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var keyShare *extension.KeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension.KeyShare); ok {
			keyShare = ks

			break
		}
	}
	require.NotNil(t, keyShare)
	require.Len(t, keyShare.ClientShares, 1)
	assert.Equal(t, selectedGroup, keyShare.ClientShares[0].Group)
}

func TestFlight13_3ParseNegotiatesVersionCipherAndKeyShare(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)
	transcript := dtlshandshake.NewTranscript()
	clientHello, _, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{state: state, cfg: cfg})
	require.NoError(t, err)
	appended, err := dtlshandshake.AppendClientHelloInitialFlights(transcript, clientHello)
	require.NoError(t, err)
	require.True(t, appended)
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello[0])

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01, 0x02, 0x03}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})
	serverHelloCanonical, err := canonicalHandshake13(rawServerHello)
	require.NoError(t, err)

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	encryptedExtensionsCanonical, err := canonicalHandshake13(rawEncryptedExtensions)
	require.NoError(t, err)
	clientKeypair := state.LocalKeypairs[group]
	require.NotNil(t, clientKeypair)
	expected, err := prf.PreMasterSecret(clientKeypair.PublicKey, serverKeypair.PrivateKey, group)
	require.NoError(t, err)
	expectedSecrets, err := deriveHandshakeTrafficSecrets13(
		cfg.LocalCipherSuites[0].HashFunc(),
		expected,
		hashTranscript13(clientHelloCanonical, serverHelloCanonical),
	)
	require.NoError(t, err)
	state.CipherSuite = cfg.LocalCipherSuites[0]
	state.KeySchedule.HandshakeTraffic = expectedSecrets
	rawFinished := marshalServerFinished13(
		t,
		state,
		2,
		clientHelloCanonical,
		serverHelloCanonical,
		encryptedExtensionsCanonical,
	)
	state.CipherSuite = nil
	state.KeySchedule.HandshakeTraffic = dtlsstate.TrafficSecrets{}
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	cache.Push(rawFinished, dtlsflight13.EpochHandshake, 2, handshake.TypeFinished, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight5, nextFlight)

	assert.Equal(t, protocol.Version1_3, state.LocalVersion)
	assert.Equal(t, []protocol.Version{protocol.Version1_3}, state.RemoteVersions)
	require.NotNil(t, state.CipherSuite)
	assert.Equal(t, cfg.LocalCipherSuites[0].ID(), state.CipherSuite.ID())
	assert.Equal(t, group, state.SelectedGroup)
	assert.Equal(t, random.RandomBytes, state.RemoteRandom.RandomBytes)
	require.NotNil(t, state.RemoteKeyEntries)
	require.Len(t, *state.RemoteKeyEntries, 1)
	assert.Equal(t, group, (*state.RemoteKeyEntries)[0].Group)

	assert.Equal(t, expected, state.KeyAgreementSecret)
	assert.NotEmpty(t, state.KeyAgreementSecret)
	assert.Equal(t, expectedSecrets, state.KeySchedule.HandshakeTraffic)
	assert.NotEqual(t, state.KeySchedule.HandshakeTraffic.Client, state.KeySchedule.HandshakeTraffic.Server)
	assert.True(t, state.CipherSuite.IsInitialized())
}

func TestFlight13_3ParseDrainsQueuedProtectedHandshakeBeforeEncryptedExtensions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(true)
	transcript := dtlshandshake.NewTranscript()
	clientHello, _, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{state: state, cfg: cfg})
	require.NoError(t, err)
	appended, err := dtlshandshake.AppendClientHelloInitialFlights(transcript, clientHello)
	require.NoError(t, err)
	require.True(t, appended)

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)
	rawServerHello := marshalServerHello(t, cfg, handshake.Random{
		RandomBytes: [handshake.RandomBytesLength]byte{0x01},
	}, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello[0])
	serverHelloCanonical, err := canonicalHandshake13(rawServerHello)
	require.NoError(t, err)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	encryptedExtensionsCanonical, err := canonicalHandshake13(rawEncryptedExtensions)
	require.NoError(t, err)
	clientKeypair := state.LocalKeypairs[group]
	require.NotNil(t, clientKeypair)
	keyAgreementSecret, err := prf.PreMasterSecret(clientKeypair.PublicKey, serverKeypair.PrivateKey, group)
	require.NoError(t, err)
	secrets, err := deriveHandshakeTrafficSecrets13(
		cfg.LocalCipherSuites[0].HashFunc(),
		keyAgreementSecret,
		hashTranscript13(clientHelloCanonical, serverHelloCanonical),
	)
	require.NoError(t, err)
	state.CipherSuite = cfg.LocalCipherSuites[0]
	state.KeySchedule.HandshakeTraffic = secrets
	rawFinished := marshalServerFinished13(
		t,
		state,
		2,
		clientHelloCanonical,
		serverHelloCanonical,
		encryptedExtensionsCanonical,
	)
	state.CipherSuite = nil
	state.KeySchedule.HandshakeTraffic = dtlsstate.TrafficSecrets{}

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	drained := false
	conn := &flight13QueuedPacketConn{
		handleQueuedPackets: func(context.Context) error {
			drained = true
			assert.True(t, state.CipherSuite.IsInitialized())
			assert.Equal(t, dtlsflight13.EpochHandshake, state.GetRemoteEpoch())
			cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
			cache.Push(rawFinished, dtlsflight13.EpochHandshake, 2, handshake.TypeFinished, false)

			return nil
		},
	}

	nextFlight, dtlsAlert, err := flight13ParseForTestWithConn(
		t, Flight3, context.Background(), conn, &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		},
	)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.True(t, drained)
	assert.Equal(t, Flight5, nextFlight)
	assert.Equal(t, 3, state.HandshakeRecvSequence)
}

func TestFlight13ClientParsesEncryptedExtensionsFromProtectedRecord(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cache := dtlsflight.NewCache()
	commonState := &dtlsstate.Common{IsClient: true, LocalVersion: protocol.Version1_3}
	conn := &Conn{
		fragmentBuffer:          newFragmentBuffer(),
		handshakeCache:          cache,
		maximumTransmissionUnit: defaultMTU,
		replayProtectionWindow:  defaultReplayProtectionWindow,
		log:                     logging.NewDefaultLoggerFactory().NewLogger("dtls"),
		state:                   &dtlsstate.State13{Common: commonState},
	}
	state, err := dtlsstate.As13(conn.state)
	require.NoError(t, err)
	transcript := dtlshandshake.NewTranscript()

	clientHello, _, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{state: state, cfg: cfg})
	require.NoError(t, err)
	appended, err := dtlshandshake.AppendClientHelloInitialFlights(transcript, clientHello)
	require.NoError(t, err)
	require.True(t, appended)
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello[0])

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)
	rawServerHello := marshalServerHello(t, cfg, handshake.Random{
		RandomBytes: [handshake.RandomBytesLength]byte{0x01},
	}, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})
	serverHelloCanonical, err := canonicalHandshake13(rawServerHello)
	require.NoError(t, err)
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	clientKeypair := state.LocalKeypairs[group]
	require.NotNil(t, clientKeypair)
	keyAgreementSecret, err := prf.PreMasterSecret(clientKeypair.PublicKey, serverKeypair.PrivateKey, group)
	require.NoError(t, err)
	secrets, err := deriveHandshakeTrafficSecrets13(
		cfg.LocalCipherSuites[0].HashFunc(),
		keyAgreementSecret,
		hashTranscript13(clientHelloCanonical, serverHelloCanonical),
	)
	require.NoError(t, err)
	peerCipherSuite := ciphersuite.NewTLSAes128GcmSha256()
	require.NoError(t, peerCipherSuite.InitFromTrafficSecrets(secrets.Client, secrets.Server, false))

	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	encryptedExtensionsCanonical, err := canonicalHandshake13(rawEncryptedExtensions)
	require.NoError(t, err)
	state.CipherSuite = cfg.LocalCipherSuites[0]
	state.KeySchedule.HandshakeTraffic = secrets
	rawFinished := marshalServerFinished13(
		t,
		state,
		2,
		clientHelloCanonical,
		serverHelloCanonical,
		encryptedExtensionsCanonical,
	)
	state.CipherSuite = nil
	state.KeySchedule.HandshakeTraffic = dtlsstate.TrafficSecrets{}

	protectedEncryptedExtensions := sealTestProtectedHandshakeRecordWithSequence(
		t, peerCipherSuite, rawEncryptedExtensions, 0,
	)
	protectedEncryptedExtensionsRaw, err := protectedEncryptedExtensions.Marshal()
	require.NoError(t, err)
	protectedFinished := sealTestProtectedHandshakeRecordWithSequence(t, peerCipherSuite, rawFinished, 1)
	protectedFinishedRaw, err := protectedFinished.Marshal()
	require.NoError(t, err)
	conn.encryptedPackets = []addrPkt{{data: protectedEncryptedExtensionsRaw}, {data: protectedFinishedRaw}}

	nextFlight, dtlsAlert, err := flight13ParseForTestWithConn(
		t, Flight3, context.Background(), adaptFlightConn(conn), &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		},
	)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight5, nextFlight)
	assert.Equal(t, 3, state.HandshakeRecvSequence)

	items := cache.Pull(dtlsflight.HandshakeCachePullRule{
		Typ:      handshake.TypeEncryptedExtensions,
		Epoch:    dtlsflight13.EpochHandshake,
		IsClient: false,
	})
	if assert.Len(t, items, 1) && assert.NotNil(t, items[0]) {
		assert.Equal(t, rawEncryptedExtensions, items[0].Data)
	}
}

func TestFlight13ClientParseAppendsNoHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)
	transcript := dtlshandshake.NewTranscript()

	pkts, dtlsAlert, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{
		state:      state,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	appended, err := dtlshandshake.AppendClientHelloInitialFlights(transcript, pkts)
	require.NoError(t, err)
	require.True(t, appended)
	clientHelloCanonical := canonicalPacketHandshake13(t, pkts[0])

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)
	rawServerHello := marshalServerHello(t, cfg, handshake.Random{
		RandomBytes: [handshake.RandomBytesLength]byte{0x01},
	}, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})
	serverHelloCanonical, err := canonicalHandshake13(rawServerHello)
	require.NoError(t, err)

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	encryptedExtensionsCanonical, err := canonicalHandshake13(rawEncryptedExtensions)
	require.NoError(t, err)
	clientKeypair := state.LocalKeypairs[group]
	require.NotNil(t, clientKeypair)
	keyAgreementSecret, err := prf.PreMasterSecret(clientKeypair.PublicKey, serverKeypair.PrivateKey, group)
	require.NoError(t, err)
	secrets, err := deriveHandshakeTrafficSecrets13(
		cfg.LocalCipherSuites[0].HashFunc(),
		keyAgreementSecret,
		hashTranscript13(clientHelloCanonical, serverHelloCanonical),
	)
	require.NoError(t, err)
	state.CipherSuite = cfg.LocalCipherSuites[0]
	state.KeySchedule.HandshakeTraffic = secrets
	rawFinished := marshalServerFinished13(
		t,
		state,
		2,
		clientHelloCanonical,
		serverHelloCanonical,
		encryptedExtensionsCanonical,
	)
	finishedCanonical, err := canonicalHandshake13(rawFinished)
	require.NoError(t, err)
	state.CipherSuite = nil
	state.KeySchedule.HandshakeTraffic = dtlsstate.TrafficSecrets{}
	cache.Push(rawFinished, dtlsflight13.EpochHandshake, 2, handshake.TypeFinished, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight1, context.Background(), &handshakeTestContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight5, nextFlight)
	expectedTranscript := append(append(append(append([]byte(nil), clientHelloCanonical...), serverHelloCanonical...),
		encryptedExtensionsCanonical...), finishedCanonical...)
	assert.Equal(t, expectedTranscript, transcript.Bytes())
}

func TestFlight13ClientParseAppendsHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)
	transcript := dtlshandshake.NewTranscript()

	pkts, dtlsAlert, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{
		state:      state,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	appended, err := dtlshandshake.AppendClientHelloInitialFlights(transcript, pkts)
	require.NoError(t, err)
	require.True(t, appended)
	clientHello1Canonical := canonicalPacketHandshake13(t, pkts[0])

	group := cfg.EllipticCurves[0]
	rawHelloRetryRequest := marshalHelloRetryRequestServerHello(t, cfg, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{SelectedGroup: &group},
	})
	helloRetryRequestCanonical, err := canonicalHandshake13(rawHelloRetryRequest)
	require.NoError(t, err)

	cache := dtlsflight.NewCache()
	cache.Push(rawHelloRetryRequest, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight1, context.Background(), &handshakeTestContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight3, nextFlight)

	clientHello2, dtlsAlert, err := flight13GenerateForTest(t, Flight3, &handshakeTestContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, clientHello2, 1)
	clientHello2Handshake, ok := clientHello2[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	clientHello2Handshake.Header.MessageSequence = 1
	require.NoError(t, dtlshandshake.AppendOutboundHandshakeFlight(transcript, true, state.CipherSuite, clientHello2))
	clientHello2Canonical := canonicalPacketHandshake13(t, clientHello2[0])

	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)
	rawServerHello := marshalServerHelloWithSequence(
		t,
		cfg,
		handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x02}},
		[]extension.Extension{
			&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
			&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
		},
		1,
	)
	serverHelloCanonical, err := canonicalHandshake13(rawServerHello)
	require.NoError(t, err)
	cache.Push(rawServerHello, cfg.InitialEpoch, 1, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 2},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 2, handshake.TypeEncryptedExtensions, false)
	encryptedExtensionsCanonical, err := canonicalHandshake13(rawEncryptedExtensions)
	require.NoError(t, err)

	clientHello1Hash := hashTranscript13(clientHello1Canonical)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	clientKeypair := state.LocalKeypairs[group]
	require.NotNil(t, clientKeypair)
	keyAgreementSecret, err := prf.PreMasterSecret(clientKeypair.PublicKey, serverKeypair.PrivateKey, group)
	require.NoError(t, err)
	secrets, err := deriveHandshakeTrafficSecrets13(
		cfg.LocalCipherSuites[0].HashFunc(),
		keyAgreementSecret,
		hashTranscript13(messageHash, helloRetryRequestCanonical, clientHello2Canonical, serverHelloCanonical),
	)
	require.NoError(t, err)
	state.CipherSuite = cfg.LocalCipherSuites[0]
	state.KeySchedule.HandshakeTraffic = secrets
	rawFinished := marshalServerFinished13(
		t,
		state,
		3,
		messageHash,
		helloRetryRequestCanonical,
		clientHello2Canonical,
		serverHelloCanonical,
		encryptedExtensionsCanonical,
	)
	finishedCanonical, err := canonicalHandshake13(rawFinished)
	require.NoError(t, err)
	state.CipherSuite = nil
	state.KeySchedule.HandshakeTraffic = dtlsstate.TrafficSecrets{}
	cache.Push(rawFinished, dtlsflight13.EpochHandshake, 3, handshake.TypeFinished, false)

	nextFlight, dtlsAlert, err = flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight5, nextFlight)

	expectedTranscript := append(append(append(append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...),
		clientHello2Canonical...), serverHelloCanonical...), encryptedExtensionsCanonical...)
	expectedTranscript = append(expectedTranscript, finishedCanonical...)
	assert.Equal(t, expectedTranscript, transcript.Bytes())
}

func TestFlight13_3ParseRejectsInvalidServerFinished(t *testing.T) {
	tests := []struct {
		name     string
		finished func(t *testing.T, f flight13ProtectedServerFlightFixture) []byte
	}{
		{
			name: "tampered Finished",
			finished: func(t *testing.T, f flight13ProtectedServerFlightFixture) []byte {
				t.Helper()

				raw := append([]byte(nil), f.rawFinished...)
				raw[len(raw)-1] ^= 0xff

				return raw
			},
		},
		{
			name: "wrong transcript",
			finished: func(t *testing.T, f flight13ProtectedServerFlightFixture) []byte {
				t.Helper()

				verifyData := finishedVerifyData13(
					t,
					f.cfg.LocalCipherSuites[0].HashFunc(),
					f.handshakeSecrets.Server,
					hashTranscript13(f.clientHelloCanonical, f.serverHelloCanonical),
				)

				return marshalFinished13(t, 2, verifyData)
			},
		},
		{
			name: "wrong handshake traffic secret",
			finished: func(t *testing.T, f flight13ProtectedServerFlightFixture) []byte {
				t.Helper()

				wrongSecret := append([]byte(nil), f.handshakeSecrets.Server...)
				wrongSecret[0] ^= 0xff
				verifyData := finishedVerifyData13(
					t,
					f.cfg.LocalCipherSuites[0].HashFunc(),
					wrongSecret,
					hashTranscript13(
						f.clientHelloCanonical,
						f.serverHelloCanonical,
						f.encryptedExtensionsCanonical,
					),
				)

				return marshalFinished13(t, 2, verifyData)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFlight13ProtectedServerFlightFixture(t)
			cache := fixture.cacheWithFinished(test.finished(t, fixture))

			nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
				state:      fixture.state,
				cache:      cache,
				cfg:        fixture.cfg,
				transcript: fixture.transcript,
			})

			require.ErrorIs(t, err, dtlserrors.ErrVerifyDataMismatch)
			require.NotNil(t, dtlsAlert)
			assert.Equal(t, alert.Fatal, dtlsAlert.Level)
			assert.Equal(t, alert.HandshakeFailure, dtlsAlert.Description)
			assert.Zero(t, nextFlight)
			assert.Equal(t, 1, fixture.state.HandshakeRecvSequence)

			expectedTranscript := append(append([]byte(nil), fixture.clientHelloCanonical...), fixture.serverHelloCanonical...)
			assert.Equal(t, expectedTranscript, fixture.transcript.Bytes())
		})
	}
}

func TestFlight13_3ParseRunsVerifyConnectionWithoutServerCertificate(t *testing.T) {
	fixture := newFlight13ProtectedServerFlightFixture(t)
	var verifyConnectionCalled bool
	fixture.cfg.VerifyConnection = adaptVerifyConnection(func(state *State) error {
		verifyConnectionCalled = true
		assert.Nil(t, state.PeerCertificates)
		assert.Equal(t, fixture.cfg.LocalCipherSuites[0].ID(), state.CipherSuiteID)

		return nil
	})

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state:      fixture.state,
		cache:      fixture.cacheWithFinished(fixture.rawFinished),
		cfg:        fixture.cfg,
		transcript: fixture.transcript,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight5, nextFlight)
	assert.True(t, verifyConnectionCalled)
	assert.Nil(t, fixture.state.PeerCertificates)
}

func TestFlight13_3ParseRejectsVerifyConnectionErrorWithoutServerCertificate(t *testing.T) {
	fixture := newFlight13ProtectedServerFlightFixture(t)
	callbackErr := errFlight13ConnectionCallbackRejected
	fixture.cfg.VerifyConnection = adaptVerifyConnection(func(*State) error {
		return callbackErr
	})

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state:      fixture.state,
		cache:      fixture.cacheWithFinished(fixture.rawFinished),
		cfg:        fixture.cfg,
		transcript: fixture.transcript,
	})

	require.ErrorIs(t, err, dtlserrors.ErrCertificateVerificationFailed)
	require.ErrorIs(t, err, callbackErr)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.BadCertificate, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.Nil(t, fixture.state.PeerCertificates)

	expectedTranscript := append(append([]byte(nil), fixture.clientHelloCanonical...), fixture.serverHelloCanonical...)
	assert.Equal(t, expectedTranscript, fixture.transcript.Bytes())
}

func TestFlight13_3ParseValidatesServerCertificate(t *testing.T) {
	certificate, err := selfsign.GenerateSelfSignedWithDNS("server.test")
	require.NoError(t, err)

	fixture := newFlight13ProtectedServerFlightFixture(t)
	fixture.cfg.RootCAs = flight13RootCAsForCertificate(t, certificate)
	fixture.cfg.ServerName = "server.test"

	var verifyPeerCalled bool
	fixture.cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		verifyPeerCalled = true
		require.Equal(t, certificate.Certificate, rawCerts)
		require.Len(t, verifiedChains, 1)
		require.NotEmpty(t, verifiedChains[0])
		assert.Equal(t, certificate.Leaf.Raw, verifiedChains[0][0].Raw)

		return nil
	}

	var verifyConnectionCalled bool
	fixture.cfg.VerifyConnection = adaptVerifyConnection(func(state *State) error {
		verifyConnectionCalled = true
		require.Equal(t, certificate.Certificate, state.PeerCertificates)
		assert.Equal(t, fixture.cfg.LocalCipherSuites[0].ID(), state.CipherSuiteID)
		state.PeerCertificates[0][0] ^= 0xff

		return nil
	})

	certificateFlight := fixture.cacheWithCertificate(t, certificate)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state:      fixture.state,
		cache:      certificateFlight.cache,
		cfg:        fixture.cfg,
		transcript: fixture.transcript,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight5, nextFlight)
	assert.True(t, verifyPeerCalled)
	assert.True(t, verifyConnectionCalled)
	assert.Equal(t, certificate.Certificate, fixture.state.PeerCertificates)

	expectedTranscript := append([]byte(nil), fixture.clientHelloCanonical...)
	for _, message := range [][]byte{
		fixture.serverHelloCanonical,
		fixture.encryptedExtensionsCanonical,
		certificateFlight.certificateCanonical,
		certificateFlight.certificateVerifyCanonical,
		certificateFlight.finishedCanonical,
	} {
		expectedTranscript = append(expectedTranscript, message...)
	}
	assert.Equal(t, expectedTranscript, fixture.transcript.Bytes())
}

func TestFlight13_3ParseRejectsWrongServerName(t *testing.T) {
	certificate, err := selfsign.GenerateSelfSignedWithDNS("server.test")
	require.NoError(t, err)

	fixture := newFlight13ProtectedServerFlightFixture(t)
	fixture.cfg.RootCAs = flight13RootCAsForCertificate(t, certificate)
	fixture.cfg.ServerName = "wrong.test"
	certificateFlight := fixture.cacheWithCertificate(t, certificate)

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state:      fixture.state,
		cache:      certificateFlight.cache,
		cfg:        fixture.cfg,
		transcript: fixture.transcript,
	})

	require.ErrorIs(t, err, dtlserrors.ErrCertificateVerificationFailed)
	var hostnameErr x509.HostnameError
	assert.True(t, errors.As(err, &hostnameErr))
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.BadCertificate, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.Nil(t, fixture.state.PeerCertificates)
	assert.Equal(t, 1, fixture.state.HandshakeRecvSequence)

	expectedTranscript := append(append([]byte(nil), fixture.clientHelloCanonical...), fixture.serverHelloCanonical...)
	assert.Equal(t, expectedTranscript, fixture.transcript.Bytes())
}

func TestFlight13_3ParseInsecureSkipVerifyStillRunsCertificateCallback(t *testing.T) {
	certificate, err := selfsign.GenerateSelfSignedWithDNS("server.test")
	require.NoError(t, err)

	fixture := newFlight13ProtectedServerFlightFixture(t)
	fixture.cfg.InsecureSkipVerify = true
	fixture.cfg.ServerName = "wrong.test"

	var verifyPeerCalled bool
	fixture.cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		verifyPeerCalled = true
		assert.Equal(t, certificate.Certificate, rawCerts)
		assert.Nil(t, verifiedChains)

		return nil
	}
	var verifyConnectionCalled bool
	fixture.cfg.VerifyConnection = adaptVerifyConnection(func(state *State) error {
		verifyConnectionCalled = true
		assert.Equal(t, certificate.Certificate, state.PeerCertificates)

		return nil
	})

	certificateFlight := fixture.cacheWithCertificate(t, certificate)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state:      fixture.state,
		cache:      certificateFlight.cache,
		cfg:        fixture.cfg,
		transcript: fixture.transcript,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight5, nextFlight)
	assert.True(t, verifyPeerCalled)
	assert.True(t, verifyConnectionCalled)
	assert.Equal(t, certificate.Certificate, fixture.state.PeerCertificates)
}

func TestFlight13_3ParseRejectsServerIdentityCallbackErrors(t *testing.T) {
	certificate, err := selfsign.GenerateSelfSignedWithDNS("server.test")
	require.NoError(t, err)
	callbackErr := errFlight13ServerIdentityCallbackReject

	tests := []struct {
		name      string
		configure func(*dtlsconfig.HandshakeConfig)
	}{
		{
			name: "VerifyPeerCertificate",
			configure: func(cfg *dtlsconfig.HandshakeConfig) {
				cfg.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error {
					return callbackErr
				}
			},
		},
		{
			name: "VerifyConnection",
			configure: func(cfg *dtlsconfig.HandshakeConfig) {
				cfg.VerifyConnection = adaptVerifyConnection(func(*State) error {
					return callbackErr
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFlight13ProtectedServerFlightFixture(t)
			fixture.cfg.RootCAs = flight13RootCAsForCertificate(t, certificate)
			fixture.cfg.ServerName = "server.test"
			test.configure(fixture.cfg)
			certificateFlight := fixture.cacheWithCertificate(t, certificate)

			nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
				state:      fixture.state,
				cache:      certificateFlight.cache,
				cfg:        fixture.cfg,
				transcript: fixture.transcript,
			})

			require.ErrorIs(t, err, dtlserrors.ErrCertificateVerificationFailed)
			require.ErrorIs(t, err, callbackErr)
			require.NotNil(t, dtlsAlert)
			assert.Equal(t, alert.Fatal, dtlsAlert.Level)
			assert.Equal(t, alert.BadCertificate, dtlsAlert.Description)
			assert.Zero(t, nextFlight)
			assert.Nil(t, fixture.state.PeerCertificates)

			expectedTranscript := append(append([]byte(nil), fixture.clientHelloCanonical...), fixture.serverHelloCanonical...)
			assert.Equal(t, expectedTranscript, fixture.transcript.Bytes())
		})
	}
}

func TestFlight13_3ParseKeepsReadingWithoutServerHello(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state: state,
		cache: dtlsflight.NewCache(),
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Zero(t, nextFlight)
}

func TestFlight13_3ParseRejectsSecondHelloRetryRequest(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)
	_, _, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	rawServerHello := marshalHelloRetryRequestServerHello(t, cfg, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrUnexpectedSecondHelloRetryRequest)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.UnexpectedMessage, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
}

func TestFlight13_3ParseRejectsWrongLegacyVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)
	_, _, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	cipherSuiteID := uint16(cfg.LocalCipherSuites[0].ID())
	serverHello := &handshake.MessageServerHello{
		Version:           protocol.Version1_0,
		Random:            handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
		Extensions: []extension.Extension{
			&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
			&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
		},
	}
	rawServerHello, err := (&handshake.Handshake{Message: serverHello}).Marshal()
	require.NoError(t, err)

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.ProtocolVersion, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
}

func TestFlight13_3ParseRejectsMissingSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)
	_, _, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.ProtocolVersion, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
}

func TestFlight13_3ParseRejectsMissingKeyShare(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)
	_, _, err := flight13GenerateForTest(t, Flight1, &handshakeTestContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrServerKeyShareMissing)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
}

func TestFlight13_3ParseRejectsUnofferedKeyShareGroup(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(false)

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Extension{
		&extension.SupportedVersions{Versions: []protocol.Version{protocol.Version1_3}, SelectedVersion: true},
		&extension.KeyShare{ServerShare: &extension.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state: state,
		cache: cache,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrServerKeyShareUnknownGroup)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
}

func TestFlight13_0ParseSelectsNegotiatedGroupWithoutGeneratingKeypair(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.P384, elliptic.P256}

	clientKeypair, err := elliptic.GenerateKeypair(elliptic.P384)
	require.NoError(t, err)
	staleServerKeypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.P384},
			},
			&extension.KeyShare{
				ClientShares: []extension.KeyShareEntry{
					{Group: elliptic.P384, KeyExchange: clientKeypair.PublicKey},
				},
			},
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
		},
	}
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)

	state := newTestState13(false)
	state.SelectedGroup = elliptic.X25519
	state.LocalKeypair = staleServerKeypair
	cache := dtlsflight.NewCache()
	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, Flight0, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight2, nextFlight)
	assert.Equal(t, elliptic.P384, state.SelectedGroup)
	assert.Same(t, staleServerKeypair, state.LocalKeypair)
	assert.Empty(t, state.KeyAgreementSecret)
}

func TestFlight13_0ParseSelectsX25519MLKEM768WithoutGeneratingKeypair(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768}

	clientKeypair, err := elliptic.GenerateKeypair(elliptic.X25519MLKEM768)
	require.NoError(t, err)

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
		Extensions: []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.X25519MLKEM768},
			},
			&extension.KeyShare{
				ClientShares: []extension.KeyShareEntry{
					{Group: elliptic.X25519MLKEM768, KeyExchange: clientKeypair.PublicKey},
				},
			},
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
		},
	}
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)

	state := newTestState13(false)
	cache := dtlsflight.NewCache()
	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, Flight0, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight2, nextFlight)
	assert.Equal(t, elliptic.X25519MLKEM768, state.SelectedGroup)
	assert.Nil(t, state.LocalKeypair)
	assert.Empty(t, state.KeyAgreementSecret)
}

func TestFlight13_0ParseSelectsServerPreferredGroupFromClientShares(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768, elliptic.X25519}

	mlkemKeypair, err := elliptic.GenerateKeypair(elliptic.X25519MLKEM768)
	require.NoError(t, err)
	x25519Keypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)

	state := newTestState13(false)
	cache := dtlsflight.NewCache()
	pushFlight13_0ClientHello(t, cache, cfg, []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
		},
		&extension.SupportedEllipticCurves{
			EllipticCurves: []elliptic.Curve{elliptic.X25519, elliptic.X25519MLKEM768},
		},
		&extension.KeyShare{
			ClientShares: []extension.KeyShareEntry{
				{Group: elliptic.X25519, KeyExchange: x25519Keypair.PublicKey},
				{Group: elliptic.X25519MLKEM768, KeyExchange: mlkemKeypair.PublicKey},
			},
		},
		&extension.SupportedVersions{
			Versions: []protocol.Version{protocol.Version1_3},
		},
	})

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, Flight0, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight2, nextFlight)
	assert.Equal(t, elliptic.X25519MLKEM768, state.SelectedGroup)
	assert.Nil(t, state.LocalKeypair)
	assert.Empty(t, state.KeyAgreementSecret)
}

func TestFlight13_0ParseRequestsPreferredGroupWhenShareMissing(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768, elliptic.X25519}

	x25519Keypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)

	state := newTestState13(false)
	cache := dtlsflight.NewCache()
	pushFlight13_0ClientHello(t, cache, cfg, []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
		},
		&extension.SupportedEllipticCurves{
			EllipticCurves: cfg.EllipticCurves,
		},
		&extension.KeyShare{
			ClientShares: []extension.KeyShareEntry{
				{Group: elliptic.X25519, KeyExchange: x25519Keypair.PublicKey},
			},
		},
		&extension.SupportedVersions{
			Versions: []protocol.Version{protocol.Version1_3},
		},
	})

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, Flight0, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight2, nextFlight)
	assert.Equal(t, elliptic.X25519MLKEM768, state.SelectedGroup)

	serverHello := serverHelloFromFlight13_2(t, state, cfg)
	keyShare, ok := findKeyShare(serverHello.Extensions)
	require.True(t, ok)
	require.NotNil(t, keyShare.SelectedGroup)
	assert.Equal(t, elliptic.X25519MLKEM768, *keyShare.SelectedGroup)
}

func TestFlight13_0ParseRejectsClientHelloWithSelectedSupportedVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
		Extensions: []extension.Extension{
			&extension.SupportedVersions{
				Versions:        []protocol.Version{protocol.Version1_3},
				SelectedVersion: true,
			},
		},
	}
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)

	state := newTestState13(false)
	cache := dtlsflight.NewCache()
	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, Flight0, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.Empty(t, state.RemoteVersions)
}

func pushFlight13_0ClientHello(
	t *testing.T,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	exts []extension.Extension,
) []byte {
	t.Helper()

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
		Extensions:         exts,
	}
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)

	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	return rawClientHello
}

func requiredClientHello13Extensions(t *testing.T, cfg *dtlsconfig.HandshakeConfig) []extension.Extension {
	t.Helper()

	clientKeypair, err := elliptic.GenerateKeypair(cfg.EllipticCurves[0])
	require.NoError(t, err)

	return []extension.Extension{
		&extension.SupportedSignatureAlgorithms{
			SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
		},
		&extension.SupportedEllipticCurves{
			EllipticCurves: cfg.EllipticCurves,
		},
		&extension.KeyShare{
			ClientShares: []extension.KeyShareEntry{
				{Group: clientKeypair.Curve, KeyExchange: clientKeypair.PublicKey},
			},
		},
		&extension.SupportedVersions{
			Versions: []protocol.Version{protocol.Version1_3},
		},
	}
}

func TestFlight13_0ParseRequiresCertificateAuthClientHelloExtensions(t *testing.T) {
	t.Run("AcceptsSignatureAlgorithmsAndSupportedGroups", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(false)
		cache := dtlsflight.NewCache()
		pushFlight13_0ClientHello(t, cache, cfg, requiredClientHello13Extensions(t, cfg))

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, Flight0, context.Background(), &handshakeTestContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, Flight2, nextFlight)
		assert.Equal(t, cfg.LocalSignatureSchemes, state.RemoteSignatureSchemes)
		assert.Equal(t, cfg.EllipticCurves, state.RemoteGroups)
	})

	t.Run("AllowsPreSharedKeyWithoutCertificateAuthExtensions", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(false)
		cache := dtlsflight.NewCache()
		binder := make([]byte, 32)
		pushFlight13_0ClientHello(t, cache, cfg, []extension.Extension{
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
			&extension.PreSharedKey{
				Identities: []extension.PskIdentity{
					{Identity: []byte("psk"), ObfuscatedTicketAge: 0},
				},
				Binders: []extension.PskBinderEntry{binder},
			},
		})

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, Flight0, context.Background(), &handshakeTestContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, Flight2, nextFlight)
	})

	t.Run("RejectsMissingSignatureAlgorithms", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(false)
		cache := dtlsflight.NewCache()
		exts := requiredClientHello13Extensions(t, cfg)[1:]
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, Flight0, context.Background(), &handshakeTestContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.ErrorIs(t, err, dtlserrors.ErrMissingClientHelloExtension)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
		assert.Zero(t, nextFlight)
	})

	t.Run("RejectsSignatureAlgorithmsCertAsSubstitute", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(false)
		cache := dtlsflight.NewCache()
		exts := requiredClientHello13Extensions(t, cfg)[1:]
		exts = append([]extension.Extension{
			&extension.SignatureAlgorithmsCert{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
		}, exts...)
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, Flight0, context.Background(), &handshakeTestContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.ErrorIs(t, err, dtlserrors.ErrMissingClientHelloExtension)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
		assert.Zero(t, nextFlight)
	})

	t.Run("RejectsMissingSupportedGroups", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(false)
		cache := dtlsflight.NewCache()
		required := requiredClientHello13Extensions(t, cfg)
		exts := []extension.Extension{required[0], required[2], required[3]}
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, Flight0, context.Background(), &handshakeTestContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.ErrorIs(t, err, dtlserrors.ErrMissingClientHelloExtension)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
		assert.Zero(t, nextFlight)
	})
}

func TestFlight13ServerParseAppendsNoHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.InsecureSkipHelloVerify = true
	state := newTestState13(false)
	cache := dtlsflight.NewCache()
	rawClientHello := pushFlight13_0ClientHello(t, cache, cfg, requiredClientHello13Extensions(t, cfg))
	clientHelloCanonical, err := canonicalHandshake13(rawClientHello)
	require.NoError(t, err)
	transcript := dtlshandshake.NewTranscript()

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, Flight0, context.Background(), &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight4, nextFlight)
	assert.Equal(t, clientHelloCanonical, transcript.Bytes())
}

func TestFlight13ServerParseAppendsHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cookie := []byte{0xde, 0xad, 0xbe, 0xef}
	state := newTestState13(false)
	state.Cookie = cookie
	cache := dtlsflight.NewCache()
	rawClientHello1 := pushFlight13_0ClientHello(t, cache, cfg, requiredClientHello13Extensions(t, cfg))
	clientHello1Canonical, err := canonicalHandshake13(rawClientHello1)
	require.NoError(t, err)
	transcript := dtlshandshake.NewTranscript()
	flightCtx := &handshakeTestContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	}

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight0, context.Background(), flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight2, nextFlight)

	helloRetryRequest, dtlsAlert, err := flight13GenerateForTest(t, Flight2, flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, helloRetryRequest, 1)
	require.NoError(
		t, dtlshandshake.AppendOutboundHandshakeFlight(transcript, false, state.CipherSuite, helloRetryRequest),
	)
	helloRetryRequestCanonical := canonicalPacketHandshake13(t, helloRetryRequest[0])

	exts := append(requiredClientHello13Extensions(t, cfg), &extension.CookieExt{Cookie: cookie})
	rawClientHello2 := pushClientHello13WithSequence(t, cache, protocol.Version1_2, 1, exts)
	clientHello2Canonical, err := canonicalHandshake13(rawClientHello2)
	require.NoError(t, err)

	nextFlight, dtlsAlert, err = flight13ParseForTest(t, Flight2, context.Background(), flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight4, nextFlight)

	clientHello1Hash := hashTranscript13(clientHello1Canonical)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	expectedTranscript := append(append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...),
		clientHello2Canonical...)
	assert.Equal(t, expectedTranscript, transcript.Bytes())
}

func serverHelloFromFlight13_2(
	t *testing.T, state *dtlsstate.State13, cfg *dtlsconfig.HandshakeConfig,
) *handshake.MessageServerHello {
	t.Helper()

	if state.CipherSuite == nil {
		state.CipherSuite = cfg.LocalCipherSuites[0]
	}
	pkts, dtlsAlert, err := flight13GenerateForTest(
		t, Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
	)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	require.NotNil(t, pkts[0].Record)
	assert.Equal(t, protocol.Version1_2, pkts[0].Record.Header.Version)

	content, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)

	serverHello, ok := content.Message.(*handshake.MessageServerHello)
	require.True(t, ok)

	return serverHello
}

func findSupportedVersions(exts []extension.Extension) (*extension.SupportedVersions, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension.SupportedVersions); ok {
			return typed, true
		}
	}

	return nil, false
}

func findKeyShare(exts []extension.Extension) (*extension.KeyShare, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension.KeyShare); ok {
			return typed, true
		}
	}

	return nil, false
}

func findCookie(exts []extension.Extension) (*extension.CookieExt, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension.CookieExt); ok {
			return typed, true
		}
	}

	return nil, false
}

func TestFlight13_2Generate(t *testing.T) {
	t.Run("ServerHelloIsHelloRetryRequest", func(t *testing.T) {
		state := newTestState13(false)
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		assert.Equal(t, protocol.Version1_2, serverHello.Version)
		assert.Equal(t, [32]byte(handshake.HelloRetryRequestRandom()), serverHello.Random.MarshalFixed())
	})

	t.Run("ResetsHandshakeSendSequence", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(false)
		state.CipherSuite = cfg.LocalCipherSuites[0]
		state.HandshakeSendSequence = 7

		_, dtlsAlert, err := flight13GenerateForTest(
			t, Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)

		assert.Equal(t, 0, state.HandshakeSendSequence)
	})

	t.Run("RejectsWithoutCipherSuite", func(t *testing.T) {
		state := newTestState13(false)
		cfg := testHandshakeConfig13(t)

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrCipherSuiteUnset)
		require.Nil(t, dtlsAlert)
		require.Nil(t, pkts)
	})

	t.Run("AlwaysIncludesSupportedVersions", func(t *testing.T) {
		state := newTestState13(false)
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		require.True(t, ok, "SupportedVersions extension must always be present")
		assert.Equal(t, []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)
		assert.True(t, supportedVersions.IsSelectedVersion())
	})

	t.Run("IncludesCipherSuiteAndCompressionMethod", func(t *testing.T) {
		state := newTestState13(false)
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		require.NotNil(t, serverHello.CipherSuiteID)
		assert.Equal(t, uint16(cfg.LocalCipherSuites[0].ID()), *serverHello.CipherSuiteID)
		require.NotNil(t, serverHello.CompressionMethod)
		assert.Equal(t, dtlsflight.DefaultCompressionMethods()[0], serverHello.CompressionMethod)

		raw, err := (&handshake.Handshake{Message: serverHello}).Marshal()
		require.NoError(t, err)

		var parsed handshake.Handshake
		require.NoError(t, parsed.Unmarshal(raw))
		parsedServerHello, ok := parsed.Message.(*handshake.MessageServerHello)
		require.True(t, ok)
		require.NotNil(t, parsedServerHello.CipherSuiteID)
		assert.Equal(t, *serverHello.CipherSuiteID, *parsedServerHello.CipherSuiteID)
	})

	t.Run("OmitsKeyShareAndCookieByDefault", func(t *testing.T) {
		state := newTestState13(false)
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		_, hasKeyShare := findKeyShare(serverHello.Extensions)
		assert.False(t, hasKeyShare, "KeyShare must be omitted when no remote key entries were offered")

		_, hasCookie := findCookie(serverHello.Extensions)
		assert.False(t, hasCookie, "Cookie must be omitted when no cookie is set")

		require.Len(t, serverHello.Extensions, 1)
	})

	t.Run("IncludesKeyShareWhenRemoteKeyEntriesPresent", func(t *testing.T) {
		state := newTestState13(false)
		state.SelectedGroup = elliptic.X25519
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		keyShare, ok := findKeyShare(serverHello.Extensions)
		require.True(t, ok, "KeyShare must be present when remote key entries were offered")
		require.NotNil(t, keyShare.SelectedGroup)
		assert.Equal(t, elliptic.X25519, *keyShare.SelectedGroup)
	})

	t.Run("IncludesCookieWhenSet", func(t *testing.T) {
		cookie := []byte{0x01, 0x02, 0x03, 0x04}
		state := newTestState13(false)
		state.Cookie = cookie
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		cookieExt, ok := findCookie(serverHello.Extensions)
		require.True(t, ok, "Cookie must be present when set on state")
		assert.Equal(t, cookie, cookieExt.Cookie)
	})

	t.Run("IncludesAllExtensionsTogether", func(t *testing.T) {
		cookie := []byte{0xaa, 0xbb}
		state := newTestState13(false)
		state.SelectedGroup = elliptic.P256
		state.Cookie = cookie
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		require.Len(t, serverHello.Extensions, 3)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		require.True(t, ok)
		assert.Equal(t, supportedVersionsRange(cfg.MinVersion, cfg.MaxVersion), supportedVersions.Versions)

		keyShare, ok := findKeyShare(serverHello.Extensions)
		require.True(t, ok)
		require.NotNil(t, keyShare.SelectedGroup)
		assert.Equal(t, elliptic.P256, *keyShare.SelectedGroup)

		cookieExt, ok := findCookie(serverHello.Extensions)
		require.True(t, ok)
		assert.Equal(t, cookie, cookieExt.Cookie)
	})
}

func TestFlight13_4Generate(t *testing.T) {
	t.Run("GeneratesServerHelloThenEncryptedExtensions", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		group := cfg.EllipticCurves[0]
		keypair, err := elliptic.GenerateKeypair(group)
		require.NoError(t, err)

		state := newTestState13(false)
		state.CipherSuite = cfg.LocalCipherSuites[0]
		state.LocalKeypair = keypair
		state.LocalRandom = handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01, 0x02, 0x03}}

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, Flight4, &handshakeTestContext13{state: state, cfg: cfg},
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		require.Len(t, pkts, 3)
		assert.Equal(t, uint16(0), pkts[0].Record.Header.Epoch)
		assert.False(t, pkts[0].ShouldEncrypt)

		serverHelloHandshake, ok := pkts[0].Record.Content.(*handshake.Handshake)
		require.True(t, ok)
		serverHello, ok := serverHelloHandshake.Message.(*handshake.MessageServerHello)
		require.True(t, ok)
		assert.Equal(t, protocol.Version1_2, serverHello.Version)
		assert.Equal(t, state.LocalRandom, serverHello.Random)
		require.NotNil(t, serverHello.CipherSuiteID)
		assert.Equal(t, uint16(cfg.LocalCipherSuites[0].ID()), *serverHello.CipherSuiteID)

		keyShare, ok := findKeyShare(serverHello.Extensions)
		require.True(t, ok)
		require.NotNil(t, keyShare.ServerShare)
		assert.Equal(t, group, keyShare.ServerShare.Group)
		assert.Equal(t, keypair.PublicKey, keyShare.ServerShare.KeyExchange)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		require.True(t, ok)
		assert.True(t, supportedVersions.IsSelectedVersion())
		assert.Equal(t, []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)

		encryptedExtensionsHandshake, ok := pkts[1].Record.Content.(*handshake.Handshake)
		require.True(t, ok)
		assert.Equal(t, dtlsflight13.EpochHandshake, pkts[1].Record.Header.Epoch)
		assert.True(t, pkts[1].ShouldEncrypt)
		assert.True(t, pkts[1].ResetLocalSequenceNumber)
		encryptedExtensions, ok := encryptedExtensionsHandshake.Message.(*handshake.MessageEncryptedExtensions)
		require.True(t, ok)
		assert.Empty(t, encryptedExtensions.Extensions)

		finishedHandshake, ok := pkts[2].Record.Content.(*handshake.Handshake)
		require.True(t, ok)
		assert.Equal(t, dtlsflight13.EpochHandshake, pkts[2].Record.Header.Epoch)
		assert.True(t, pkts[2].ShouldEncrypt)
		assert.False(t, pkts[2].ResetLocalSequenceNumber)
		_, ok = finishedHandshake.Message.(*handshake.MessageFinished)
		require.True(t, ok)
	})

	t.Run("RejectsWithoutCipherSuite", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(false)

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, Flight4, &handshakeTestContext13{state: state, cfg: cfg},
		)
		require.ErrorIs(t, err, dtlserrors.ErrCipherSuiteUnset)
		require.Nil(t, dtlsAlert)
		require.Nil(t, pkts)
	})

	t.Run("RejectsWithoutLocalKeypair", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(false)
		state.CipherSuite = cfg.LocalCipherSuites[0]

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, Flight4, &handshakeTestContext13{state: state, cfg: cfg},
		)
		require.ErrorIs(t, err, dtlserrors.ErrServerKeyShareMissing)
		require.Nil(t, dtlsAlert)
		require.Nil(t, pkts)
	})
}

func TestFlight13ServerFlight4UsesHandshakeEpoch(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	group := cfg.EllipticCurves[0]
	keypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	state := newTestState13(false)
	state.CipherSuite = cfg.LocalCipherSuites[0]
	state.LocalKeypair = keypair
	state.LocalRandom = handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}

	pkts, dtlsAlert, err := flight13GenerateForTest(
		t, Flight4, &handshakeTestContext13{state: state, cfg: cfg},
	)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 3)

	assert.Equal(t, uint16(0), pkts[0].Record.Header.Epoch)
	assert.False(t, pkts[0].ShouldEncrypt)
	assert.Equal(t, dtlsflight13.EpochHandshake, pkts[1].Record.Header.Epoch)
	assert.True(t, pkts[1].ShouldEncrypt)
	assert.True(t, pkts[1].ResetLocalSequenceNumber)
	assert.Equal(t, dtlsflight13.EpochHandshake, pkts[2].Record.Header.Epoch)
	assert.True(t, pkts[2].ShouldEncrypt)
	assert.False(t, pkts[2].ResetLocalSequenceNumber)
}

func pushClientHello13(
	t *testing.T,
	cache *dtlsflight.Cache,
	version protocol.Version,
	exts []extension.Extension,
) {
	t.Helper()

	pushClientHello13WithSequence(t, cache, version, 0, exts)
}

func pushClientHello13WithSequence(
	t *testing.T,
	cache *dtlsflight.Cache,
	version protocol.Version,
	seq uint16,
	exts []extension.Extension,
) []byte {
	t.Helper()

	content := &handshake.Handshake{
		Header: handshake.Header{MessageSequence: seq},
		Message: &handshake.MessageClientHello{
			Version:            version,
			Random:             handshake.Random{},
			CipherSuiteIDs:     []uint16{},
			CompressionMethods: dtlsflight.DefaultCompressionMethods(),
			Extensions:         exts,
		},
	}

	raw, err := content.Marshal()
	require.NoError(t, err)

	cache.Push(raw, 0, seq, handshake.TypeClientHello, true)

	return raw
}

func flight13_2Context(
	state *dtlsstate.State13, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig,
) *handshakeTestContext13 {
	return &handshakeTestContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: dtlshandshake.NewTranscript(),
	}
}

func TestFlight13_2Parse(t *testing.T) {
	cookie := []byte{0xde, 0xad, 0xbe, 0xef}

	t.Run("AdvancesToFlight4OnMatchingCookie", func(t *testing.T) {
		state := newTestState13(false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension.CookieExt{Cookie: cookie})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, Flight4, next)
		assert.Equal(t, 1, state.HandshakeRecvSequence)
	})

	t.Run("GeneratesX25519MLKEM768KeypairAfterMatchingCookie", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768}
		clientKeypair, err := elliptic.GenerateKeypair(elliptic.X25519MLKEM768)
		require.NoError(t, err)

		state := newTestState13(false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		pushClientHello13(t, cache, protocol.Version1_2, []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
			&extension.SupportedEllipticCurves{
				EllipticCurves: cfg.EllipticCurves,
			},
			&extension.KeyShare{
				ClientShares: []extension.KeyShareEntry{
					{Group: elliptic.X25519MLKEM768, KeyExchange: clientKeypair.PublicKey},
				},
			},
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, Flight4, next)
		require.NotNil(t, state.LocalKeypair)
		assert.Equal(t, elliptic.X25519MLKEM768, state.SelectedGroup)
		assert.Equal(t, elliptic.X25519MLKEM768, state.LocalKeypair.Curve)
		assert.Len(t, state.LocalKeypair.PublicKey, elliptic.X25519MLKEM768ServerPublicKeySize)

		clientSecret, err := prf.PreMasterSecret(
			state.LocalKeypair.PublicKey,
			clientKeypair.PrivateKey,
			elliptic.X25519MLKEM768,
		)
		require.NoError(t, err)
		assert.Equal(t, clientSecret, state.KeyAgreementSecret)
		assert.Len(t, state.KeyAgreementSecret, elliptic.X25519MLKEM768SharedSecretSize)
	})

	t.Run("RejectsUnsupportedSupportedGroupsAfterMatchingCookie", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		cfg.EllipticCurves = []elliptic.Curve{elliptic.P256}
		clientKeypair, err := elliptic.GenerateKeypair(elliptic.P384)
		require.NoError(t, err)

		state := newTestState13(false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		pushClientHello13(t, cache, protocol.Version1_2, []extension.Extension{
			&extension.SupportedSignatureAlgorithms{
				SignatureHashAlgorithms: cfg.LocalSignatureSchemes,
			},
			&extension.SupportedEllipticCurves{
				EllipticCurves: []elliptic.Curve{elliptic.P384},
			},
			&extension.KeyShare{
				ClientShares: []extension.KeyShareEntry{
					{Group: elliptic.P384, KeyExchange: clientKeypair.PublicKey},
				},
			},
			&extension.SupportedVersions{
				Versions: []protocol.Version{protocol.Version1_3},
			},
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrNoSupportedEllipticCurves)
		assert.Equal(t, Flight(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlsAlert)
		assert.Empty(t, state.KeyAgreementSecret)
		assert.Nil(t, state.LocalKeypair)
		assert.Zero(t, state.SelectedGroup)
	})

	t.Run("KeepsWaitingWhenNoClientHelloCached", func(t *testing.T) {
		state := newTestState13(false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		next, dtlsAlert, err := flight13ParseForTest(
			t, Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, Flight(0), next)
		assert.Equal(t, 0, state.HandshakeRecvSequence)
	})

	t.Run("KeepsWaitingWhenCookieNotYetEchoed", func(t *testing.T) {
		state := newTestState13(false)
		state.Cookie = cookie
		state.ServerName = "original.example"
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension.ServerName{ServerName: "poison.example"})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, Flight(0), next)
		assert.Equal(t, 0, state.HandshakeRecvSequence)
		assert.Equal(t, "original.example", state.ServerName)
		assert.Empty(t, state.RemoteSignatureSchemes)
		assert.Empty(t, state.RemoteGroups)
	})

	t.Run("RejectsCookieMismatch", func(t *testing.T) {
		state := newTestState13(false)
		state.Cookie = cookie
		state.ServerName = "original.example"
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension.ServerName{ServerName: "poison.example"},
			&extension.CookieExt{Cookie: []byte{0x00, 0x01, 0x02, 0x03}})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrCookieMismatch)
		assert.Equal(t, Flight(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.AccessDenied}, dtlsAlert)
		assert.Equal(t, 0, state.HandshakeRecvSequence)
		assert.Equal(t, "original.example", state.ServerName)
		assert.Empty(t, state.RemoteSignatureSchemes)
		assert.Empty(t, state.RemoteGroups)
	})

	t.Run("RejectsUnsupportedVersion", func(t *testing.T) {
		state := newTestState13(false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version{Major: 0xfe, Minor: 0xfd - 1}, []extension.Extension{
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
		assert.Equal(t, Flight(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlsAlert)
	})

	t.Run("RejectsMissingCertificateAuthExtensions", func(t *testing.T) {
		state := newTestState13(false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version1_2, []extension.Extension{
			&extension.CookieExt{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrMissingClientHelloExtension)
		assert.Equal(t, Flight(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
	})
}
