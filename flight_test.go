// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"hash"
	"slices"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsfragmentbuffer "github.com/pion/dtls/v3/internal/fragmentbuffer"
	dtlshandshake "github.com/pion/dtls/v3/internal/handshake"
	dtlscrypto "github.com/pion/dtls/v3/internal/handshakecrypto"
	"github.com/pion/dtls/v3/internal/negotiation"
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
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
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

type handshakeTestContext13 struct {
	state      *dtlsstate.State13
	cache      *dtlsflight.Cache
	cfg        *dtlsconfig.HandshakeConfig
	transcript *dtlshandshake.Transcript
}

func newTestState13(tb testing.TB, isClient bool) *dtlsstate.State13 {
	tb.Helper()

	state := dtlsstate.NewState13(isClient)
	_, snapshot, err := negotiation.FinalizeClientHello(withExtensions(&handshake.MessageClientHello{
		CipherSuiteIDs: []uint16{uint16(ciphersuite.TLS_AES_128_GCM_SHA256)},
	}, []extension.Value{
		&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
		&extension.SignatureAlgorithms{Schemes: []uint16{0x0403}},
		&extension.SupportedGroups{Groups: slices.Clone(testCurves13)},
		&extension13.ClientKeyShare{},
	}), nil)
	require.NoError(tb, err)
	require.NoError(tb, state.LocalClientHelloSnapshots.Record(snapshot))
	require.NoError(tb, state.RemoteClientHelloSnapshots.Record(snapshot))

	return &state
}

func omitInitialKeyShares() func(handshake.MessageClientHello) handshake.Message {
	initial := true

	return func(clientHello handshake.MessageClientHello) handshake.Message {
		if initial {
			initial = false
			for i, value := range clientHello.Extensions {
				if value.ExtensionType() == extension.TypeKeyShare {
					extensions := clientHello.Extensions
					extensions[i] = &extension13.ClientKeyShare{}
					clientHello.Extensions = extensions
				}
			}
		}

		return &clientHello
	}
}

func flight13ParseForTest(
	testingT require.TestingT,
	flight dtlsflight13.Flight,
	ctx context.Context,
	flightCtx *handshakeTestContext13,
) (dtlsflight13.Flight, *alert.Alert, error) {
	return flight13ParseForTestWithConn(testingT, flight, ctx, nil, flightCtx)
}

func flight13ParseForTestWithConn(
	testingT require.TestingT,
	flight dtlsflight13.Flight,
	ctx context.Context,
	conn dtlsflight.Conn,
	flightCtx *handshakeTestContext13,
) (dtlsflight13.Flight, *alert.Alert, error) {
	if helper, ok := testingT.(interface{ Helper() }); ok {
		helper.Helper()
	}

	nextFlight, dtlsAlert, err, ok := dtlsflight13.Parse(
		ctx,
		flight,
		conn,
		dtlsflight13.ParseDependencies{
			State:  flightCtx.state,
			Cache:  flightCtx.cache,
			Config: flightCtx.cfg,
			Hooks: dtlsflight13.ParseHooks{
				InboundHandshake: func(cipherSuite dtlsconfig.CipherSuite, items []dtlsflight.DecodedHandshakeCacheItem) error {
					return dtlshandshake.AppendVerifiedInboundHandshakeCacheItems(flightCtx.transcript, cipherSuite, items)
				},
				ProtectedHandshake: func(cipherSuite dtlsconfig.CipherSuite, items []dtlsflight.DecodedHandshakeCacheItem) error {
					return dtlshandshake.VerifyAndAppendProtectedHandshakeCacheItems(
						flightCtx.transcript,
						flightCtx.state,
						flightCtx.cfg,
						cipherSuite,
						items,
					)
				},
				HandshakeTrafficSecretDeriver: func(state *dtlsstate.State13) error {
					return dtlshandshake.DeriveAndStoreHandshakeTrafficSecrets(state, flightCtx.transcript)
				},
				HandshakeRecordProtectionInitializer: dtlshandshake.InitHandshakeRecordProtection,
			},
		},
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
	flight dtlsflight13.Flight,
	flightCtx *handshakeTestContext13,
) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	if helper, ok := testingT.(interface{ Helper() }); ok {
		helper.Helper()
	}

	gen, _, ok := dtlsflight13.GetGenerator(flight)
	require.True(testingT, ok)

	return gen(nil, flightCtx.state, flightCtx.cache, flightCtx.cfg)
}

func retryRequestForTest(
	tb testing.TB,
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
	initial negotiation.ClientHelloSnapshot,
	group elliptic.Curve,
) negotiation.RetryRequest {
	tb.Helper()
	id := uint16(cfg.LocalCipherSuites[0].ID())
	extensions := []extension.Value{&extension13.SelectedVersion{Version: protocol.Version1_3}}
	if group != 0 {
		extensions = append(extensions, &extension13.RetryKeyShare{SelectedGroup: group})
	}
	if state.Cookie != nil {
		extensions = append(extensions, &extension13.Cookie{Cookie: state.Cookie})
	}
	request, err := negotiation.ValidateHelloRetryRequest(
		initial, withExtensions(&handshake.MessageServerHello{
			CipherSuiteID: &id,
		}, extensions),
	)
	require.NoError(tb, err)

	return request
}

func canonicalPacketHandshake13(t *testing.T, p *dtlsflight.Outbound) []byte {
	t.Helper()

	content, ok := p.Content.(*handshake.Handshake)
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
	state := newTestState13(t, true)
	transcript := dtlshandshake.NewTranscript()
	clientHello, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})
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
	}, []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
		&extension13.ServerKeyShare{Share: extension13.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
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
		LocalSignatureSchemes:       signaturehash.Algorithms(),
		LocalCertSignatureSchemes:   nil,
		LocalSRTPProtectionProfiles: nil,
	}
}

func TestFlight13_5GenerateSelectsClientCertificateBySignatureScheme(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaCertificate, err := selfsign.SelfSign(rsaKey)
	require.NoError(t, err)
	ecdsaCertificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	ecdsaSHA256 := signaturehash.Algorithm{
		Hash:      dtlshash.SHA256,
		Signature: signature.ECDSA,
	}
	request := withExtensions(&handshake.MessageCertificateRequest13{
		CertificateRequestContext: []byte("request"),
	}, []extension.Value{
		&extension.SignatureAlgorithms{
			Schemes: dtlsflight.SignatureSchemeIDs([]signaturehash.Algorithm{ecdsaSHA256}),
		},
	})
	cfg := testHandshakeConfig13(t)
	cfg.LocalCertificates = []tls.Certificate{rsaCertificate, ecdsaCertificate}
	state := newTestState13(t, true)
	state.RemoteCertificateRequest = request

	packets, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight5, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, packets, 3)

	certificateHandshake, ok := packets[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	certificateMessage, ok := certificateHandshake.Message.(*handshake.MessageCertificate13)
	require.True(t, ok)
	require.Len(t, certificateMessage.CertificateList, 1)
	assert.Equal(t, ecdsaCertificate.Certificate[0], certificateMessage.CertificateList[0].CertificateData)

	verifyHandshake, ok := packets[1].Content.(*handshake.Handshake)
	require.True(t, ok)
	verifyMessage, ok := verifyHandshake.Message.(*handshake.MessageCertificateVerify)
	require.True(t, ok)
	assert.Equal(t, ecdsaSHA256.Hash, verifyMessage.HashAlgorithm)
	assert.Equal(t, ecdsaSHA256.Signature, verifyMessage.SignatureAlgorithm)
	assert.Same(t, ecdsaCertificate.PrivateKey, packets[1].CertificateVerifySigner)
}

func marshalHelloRetryRequestServerHello(
	t *testing.T,
	cfg *dtlsconfig.HandshakeConfig,
	extensions []extension.Value,
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
	extensions []extension.Value,
) []byte {
	t.Helper()

	return marshalServerHelloWithSequence(t, cfg, random, extensions, 0)
}

func marshalServerHelloWithSequence(
	t *testing.T,
	cfg *dtlsconfig.HandshakeConfig,
	random handshake.Random,
	extensions []extension.Value,
	seq uint16,
) []byte {
	t.Helper()

	cipherSuiteID := uint16(cfg.LocalCipherSuites[0].ID())
	serverHello := withExtensions(&handshake.MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            random,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
	}, extensions)
	rawServerHello, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: seq},
		Message: serverHello,
	}).Marshal()
	require.NoError(t, err)

	return rawServerHello
}

func generateFlight13_1ClientHello(t *testing.T, cfg *dtlsconfig.HandshakeConfig) *handshake.MessageClientHello {
	t.Helper()

	state := newTestState13(t, false)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	return clientHello
}

func TestFlight13_1GenerateClientHelloIncludesRequiredExtensions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(t, false)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var supportedVersions *extension13.OfferedVersions
	var supportedGroups *extension.SupportedGroups
	for _, ext := range clientHello.Extensions {
		switch typed := ext.(type) {
		case *extension13.OfferedVersions:
			supportedVersions = typed
		case *extension.SupportedGroups:
			supportedGroups = typed
		}
	}
	require.NotNil(t, supportedVersions)
	assert.Equal(t, []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)
	require.NotNil(t, supportedGroups)
	assert.Equal(t, cfg.EllipticCurves, supportedGroups.Groups)
}

func TestFlight13_1GenerateClientHelloIncludesSignatureAlgorithms(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.LocalCertSignatureSchemes = cfg.LocalSignatureSchemes[:1]

	clientHello := generateFlight13_1ClientHello(t, cfg)

	var signatureAlgorithms *extension.SignatureAlgorithms
	var signatureAlgorithmsCert *extension.CertificateSignatureAlgorithms
	for _, ext := range clientHello.Extensions {
		switch typed := ext.(type) {
		case *extension.SignatureAlgorithms:
			signatureAlgorithms = typed
		case *extension.CertificateSignatureAlgorithms:
			signatureAlgorithmsCert = typed
		}
	}

	require.NotNil(t, signatureAlgorithms)
	assert.Equal(t, dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes), signatureAlgorithms.Schemes)
	require.NotNil(t, signatureAlgorithmsCert)
	assert.Equal(t, dtlsflight.SignatureSchemeIDs(cfg.LocalCertSignatureSchemes), signatureAlgorithmsCert.Schemes)
}

func TestFlight13_1GenerateRetainsPrivateKeysForAdvertisedShares(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(t, false)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var keyShare *extension13.ClientKeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension13.ClientKeyShare); ok {
			keyShare = ks

			break
		}
	}
	require.NotNil(t, keyShare)
	require.Len(t, keyShare.Shares, len(cfg.EllipticCurves))
	require.Len(t, state.LocalKeyEntries, len(keyShare.Shares))
	require.Len(t, state.LocalKeypairs, len(keyShare.Shares))

	for _, entry := range keyShare.Shares {
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
	state := newTestState13(t, false)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var keyShare *extension13.ClientKeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension13.ClientKeyShare); ok {
			keyShare = ks

			break
		}
	}
	require.NotNil(t, keyShare)
	require.Len(t, keyShare.Shares, 1)
	assert.Equal(t, elliptic.X25519MLKEM768, keyShare.Shares[0].Group)
	assert.Len(t, keyShare.Shares[0].KeyExchange, elliptic.X25519MLKEM768ClientPublicKeySize)

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
	cfg.ClientHelloMessageHook = omitInitialKeyShares()

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Value{
			&extension13.SelectedVersion{Version: protocol.Version1_3},
			&extension13.RetryKeyShare{SelectedGroup: selectedGroup},
		},
	)

	state := newTestState13(t, false)
	_, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight1, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight3, nextFlight)
	assert.Equal(t, selectedGroup, state.HelloRetryRequest.SelectedGroup)
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithoutSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Value{
			&extension13.RetryKeyShare{SelectedGroup: selectedGroup},
		},
	)

	state := newTestState13(t, false)
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight1, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.ErrorIs(t, err, dtlserrors.ErrMissingSupportedVersionsExtension)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.MissingExtension, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.False(t, state.HasRemoteKeyEntries)
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithWrongSelectedVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Value{
			&extension13.SelectedVersion{Version: protocol.Version1_2},
			&extension13.RetryKeyShare{SelectedGroup: selectedGroup},
		},
	)

	state := newTestState13(t, false)
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight1, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
	require.NotNil(t, dtlsAlert)
	assert.Equal(t, alert.Fatal, dtlsAlert.Level)
	assert.Equal(t, alert.ProtocolVersion, dtlsAlert.Description)
	assert.Zero(t, nextFlight)
	assert.False(t, state.HasRemoteKeyEntries)
}

func TestFlight13_1ParseRejectsHelloRetryRequestWithClientHelloSupportedVersionsEncoding(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	selectedGroup := elliptic.P384

	rawServerHello := marshalHelloRetryRequestServerHello(
		t,
		cfg,
		[]extension.Value{
			extension.Raw{
				Type: extension.TypeSupportedVersions,
				Data: []byte{
					0x02,       // ClientHello vector length
					0xfe, 0xfc, // DTLS v1.3
				},
			},
			&extension13.RetryKeyShare{SelectedGroup: selectedGroup},
		},
	)

	parsed := &handshake.Handshake{}
	err := parsed.Unmarshal(rawServerHello)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidSupportedVersionsFormat)
}

func TestFlight13_3GenerateRejectsWithoutCommonVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(t, false)
	require.NoError(t, state.LocalRandom.Populate())

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight3, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.ErrorIs(t, err, dtlserrors.ErrNoCommonProtocolVersion)
	require.Nil(t, dtlsAlert)
	require.Nil(t, pkts)
}

func TestFlight13_3GenerateIncludesCookieAndSupportedVersions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(t, false)
	state.Cookie = []byte{0x01, 0x02, 0x03, 0x04}
	state.RemoteVersions = []protocol.Version{protocol.Version1_3}
	state.HelloRetryRequest = retryRequestForTest(
		t, state, cfg, state.LocalClientHelloSnapshots.Initial(), 0,
	)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight3, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var supportedVersions *extension13.OfferedVersions
	for _, ext := range clientHello.Extensions {
		if sv, ok := ext.(*extension13.OfferedVersions); ok {
			supportedVersions = sv

			break
		}
	}
	require.NotNil(t, supportedVersions)
	assert.Equal(t, []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)

	var signatureAlgorithms *extension.SignatureAlgorithms
	for _, ext := range clientHello.Extensions {
		if sigAlgs, ok := ext.(*extension.SignatureAlgorithms); ok {
			signatureAlgorithms = sigAlgs

			break
		}
	}
	require.NotNil(t, signatureAlgorithms)
	assert.Equal(t, []uint16{0x0403}, signatureAlgorithms.Schemes)

	var cookieExt *extension13.Cookie
	for _, ext := range clientHello.Extensions {
		if c, ok := ext.(*extension13.Cookie); ok {
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

	state := newTestState13(t, false)
	state.RemoteVersions = []protocol.Version{protocol.Version1_3}
	state.HelloRetryRequest = retryRequestForTest(
		t, state, cfg, state.LocalClientHelloSnapshots.Initial(), selectedGroup,
	)

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight3, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	hand, ok := pkts[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var keyShare *extension13.ClientKeyShare
	for _, ext := range clientHello.Extensions {
		if ks, ok := ext.(*extension13.ClientKeyShare); ok {
			keyShare = ks

			break
		}
	}
	require.NotNil(t, keyShare)
	require.Len(t, keyShare.Shares, 1)
	assert.Equal(t, selectedGroup, keyShare.Shares[0].Group)
	assert.NotEmpty(t, keyShare.Shares[0].KeyExchange)

	selectedKeypair := state.LocalKeypairs[selectedGroup]
	require.NotNil(t, selectedKeypair)
	assert.Equal(t, keyShare.Shares[0].KeyExchange, selectedKeypair.PublicKey)
}

func TestFlight13_3ParseNegotiatesVersionCipherAndKeyShare(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(t, false)
	transcript := dtlshandshake.NewTranscript()
	clientHello, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})
	require.NoError(t, err)
	appended, err := dtlshandshake.AppendClientHelloInitialFlights(transcript, clientHello)
	require.NoError(t, err)
	require.True(t, appended)
	clientHelloCanonical := canonicalPacketHandshake13(t, clientHello[0])

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01, 0x02, 0x03}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
		&extension13.ServerKeyShare{Share: extension13.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
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
	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight(0), nextFlight)
	assert.Equal(t, 1, state.HandshakeRecvSequence)
	assert.Equal(t, dtlsflight13.EpochHandshake, state.RemoteEpoch())

	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	cache.Push(rawFinished, dtlsflight13.EpochHandshake, 2, handshake.TypeFinished, false)
	nextFlight, dtlsAlert, err = flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight5, nextFlight)

	assert.Equal(t, protocol.Version1_3, state.LocalVersion)
	assert.Equal(t, []protocol.Version{protocol.Version1_3}, state.RemoteVersions)
	require.NotNil(t, state.CipherSuite)
	assert.Equal(t, cfg.LocalCipherSuites[0].ID(), state.CipherSuite.ID())
	assert.Equal(t, group, state.SelectedGroup)
	assert.Equal(t, random.RandomBytes, state.RemoteRandom.RandomBytes)
	require.True(t, state.HasRemoteKeyEntries)
	require.Len(t, state.RemoteKeyEntries, 1)
	assert.Equal(t, group, state.RemoteKeyEntries[0].Group)

	assert.Equal(t, expected, state.KeyAgreementSecret)
	assert.NotEmpty(t, state.KeyAgreementSecret)
	assert.Equal(t, expectedSecrets, state.KeySchedule.HandshakeTraffic)
	assert.NotEqual(t, state.KeySchedule.HandshakeTraffic.Client, state.KeySchedule.HandshakeTraffic.Server)
	assert.True(t, state.CipherSuite.IsInitialized())
}

func TestFlight13_3ParseDrainsQueuedProtectedHandshakeBeforeEncryptedExtensions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := newTestState13(t, true)
	transcript := dtlshandshake.NewTranscript()
	clientHello, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})
	require.NoError(t, err)
	appended, err := dtlshandshake.AppendClientHelloInitialFlights(transcript, clientHello)
	require.NoError(t, err)
	require.True(t, appended)

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)
	rawServerHello := marshalServerHello(t, cfg, handshake.Random{
		RandomBytes: [handshake.RandomBytesLength]byte{0x01},
	}, []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
		&extension13.ServerKeyShare{Share: extension13.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
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
			assert.Equal(t, dtlsflight13.EpochHandshake, state.RemoteEpoch())
			cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
			cache.Push(rawFinished, dtlsflight13.EpochHandshake, 2, handshake.TypeFinished, false)

			return nil
		},
	}

	nextFlight, dtlsAlert, err := flight13ParseForTestWithConn(
		t, dtlsflight13.Flight3, context.Background(), conn, &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		},
	)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.True(t, drained)
	assert.Equal(t, dtlsflight13.Flight5, nextFlight)
	assert.Equal(t, 3, state.HandshakeRecvSequence)
}

func TestFlight13ClientParsesEncryptedExtensionsFromProtectedRecord(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cache := dtlsflight.NewCache()
	commonState := &dtlsstate.Common{IsClient: true, LocalVersion: protocol.Version1_3}
	conn := &Conn{
		fragmentBuffer:          dtlsfragmentbuffer.New(),
		handshakeCache:          cache,
		maximumTransmissionUnit: defaultMTU,
		replayProtectionWindow:  defaultReplayProtectionWindow,
		log:                     logging.NewDefaultLoggerFactory().NewLogger("dtls"),
		state:                   &dtlsstate.State13{Common: commonState},
	}
	state, err := dtlsstate.As13(conn.state)
	require.NoError(t, err)
	transcript := dtlshandshake.NewTranscript()

	clientHello, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})
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
	}, []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
		&extension13.ServerKeyShare{Share: extension13.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
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
	peerWriteProtection, err := peerCipherSuite.NewRecordProtection(secrets.Server)
	require.NoError(t, err)

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
		t, peerWriteProtection, rawEncryptedExtensions, 0,
	)
	protectedEncryptedExtensionsRaw, err := protectedEncryptedExtensions.Marshal()
	require.NoError(t, err)
	protectedFinished := sealTestProtectedHandshakeRecordWithSequence(t, peerWriteProtection, rawFinished, 1)
	protectedFinishedRaw, err := protectedFinished.Marshal()
	require.NoError(t, err)
	conn.encryptedPackets = []addrPkt{{data: protectedEncryptedExtensionsRaw}, {data: protectedFinishedRaw}}

	nextFlight, dtlsAlert, err := flight13ParseForTestWithConn(
		t, dtlsflight13.Flight3, context.Background(), adaptFlightConn(conn), &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		},
	)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight5, nextFlight)
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
	state := newTestState13(t, false)
	transcript := dtlshandshake.NewTranscript()

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
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
	}, []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
		&extension13.ServerKeyShare{Share: extension13.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
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
	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight1, context.Background(), &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight5, nextFlight)
	expectedTranscript := append(append(append(append([]byte(nil), clientHelloCanonical...), serverHelloCanonical...),
		encryptedExtensionsCanonical...), finishedCanonical...)
	assert.Equal(t, expectedTranscript, transcript.Bytes())
}

func TestFlight13ClientParseAppendsHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.ClientHelloMessageHook = omitInitialKeyShares()
	state := newTestState13(t, false)
	transcript := dtlshandshake.NewTranscript()

	pkts, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
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
	rawHelloRetryRequest := marshalHelloRetryRequestServerHello(t, cfg, []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
		&extension13.RetryKeyShare{SelectedGroup: group},
	})
	helloRetryRequestCanonical, err := canonicalHandshake13(rawHelloRetryRequest)
	require.NoError(t, err)

	cache := dtlsflight.NewCache()
	cache.Push(rawHelloRetryRequest, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight1, context.Background(), &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight3, nextFlight)

	clientHello2, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight3, &handshakeTestContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, clientHello2, 1)
	clientHello2Handshake, ok := clientHello2[0].Content.(*handshake.Handshake)
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
		[]extension.Value{
			&extension13.SelectedVersion{Version: protocol.Version1_3},
			&extension13.ServerKeyShare{Share: extension13.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
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

	nextFlight, dtlsAlert, err = flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight5, nextFlight)

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

			nextFlight, dtlsAlert, err := flight13ParseForTest(
				t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
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

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
			state:      fixture.state,
			cache:      fixture.cacheWithFinished(fixture.rawFinished),
			cfg:        fixture.cfg,
			transcript: fixture.transcript,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight5, nextFlight)
	assert.True(t, verifyConnectionCalled)
	assert.Nil(t, fixture.state.PeerCertificates)
}

func TestFlight13_3ParseRejectsVerifyConnectionErrorWithoutServerCertificate(t *testing.T) {
	fixture := newFlight13ProtectedServerFlightFixture(t)
	callbackErr := errFlight13ConnectionCallbackRejected
	fixture.cfg.VerifyConnection = adaptVerifyConnection(func(*State) error {
		return callbackErr
	})

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
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
	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
			state:      fixture.state,
			cache:      certificateFlight.cache,
			cfg:        fixture.cfg,
			transcript: fixture.transcript,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight5, nextFlight)
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

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
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
	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
			state:      fixture.state,
			cache:      certificateFlight.cache,
			cfg:        fixture.cfg,
			transcript: fixture.transcript,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight5, nextFlight)
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

			nextFlight, dtlsAlert, err := flight13ParseForTest(
				t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
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
	state := newTestState13(t, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
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
	state := newTestState13(t, false)
	_, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	rawServerHello := marshalHelloRetryRequestServerHello(t, cfg, []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
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
	state := newTestState13(t, false)
	_, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{state: state, cfg: cfg})
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
	}
	serverHello.Extensions = []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
		&extension13.ServerKeyShare{Share: extension13.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
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
	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
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
	state := newTestState13(t, false)
	_, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, nil)

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
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
	state := newTestState13(t, false)
	_, _, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{state: state, cfg: cfg})
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
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
	state := newTestState13(t, false)
	_, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight1, &handshakeTestContext13{
		state: state,
		cfg:   cfg,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)

	group := elliptic.X25519MLKEM768
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)

	random := handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}}
	rawServerHello := marshalServerHello(t, cfg, random, []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
		&extension13.ServerKeyShare{Share: extension13.KeyShareEntry{Group: group, KeyExchange: serverKeypair.PublicKey}},
	})

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
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

	extensions := []extension.Value{
		&extension.SignatureAlgorithms{
			Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes),
		},
		&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.P384}},
		&extension13.ClientKeyShare{
			Shares: []extension13.KeyShareEntry{
				{Group: elliptic.P384, KeyExchange: clientKeypair.PublicKey},
			},
		},
		&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
	}
	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
	}
	clientHello.Extensions = extensions
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)

	state := newTestState13(t, false)
	state.SelectedGroup = elliptic.X25519
	state.LocalKeypair = staleServerKeypair
	cache := dtlsflight.NewCache()
	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight2, nextFlight)
	assert.Equal(t, elliptic.P384, state.SelectedGroup)
	assert.Same(t, staleServerKeypair, state.LocalKeypair)
	assert.Empty(t, state.KeyAgreementSecret)
}

func TestFlight13_0ParseSelectsX25519MLKEM768WithoutGeneratingKeypair(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768}

	clientKeypair, err := elliptic.GenerateKeypair(elliptic.X25519MLKEM768)
	require.NoError(t, err)

	extensions := []extension.Value{
		&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes)},
		&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519MLKEM768}},
		&extension13.ClientKeyShare{
			Shares: []extension13.KeyShareEntry{
				{Group: elliptic.X25519MLKEM768, KeyExchange: clientKeypair.PublicKey},
			},
		},
		&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
	}
	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
	}
	clientHello.Extensions = extensions
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)

	state := newTestState13(t, false)
	cache := dtlsflight.NewCache()
	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight2, nextFlight)
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

	state := newTestState13(t, false)
	cache := dtlsflight.NewCache()
	pushFlight13_0ClientHello(t, cache, cfg, []extension.Value{
		&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes)},
		&extension.SupportedGroups{
			Groups: []elliptic.Curve{elliptic.X25519, elliptic.X25519MLKEM768},
		},
		&extension13.ClientKeyShare{
			Shares: []extension13.KeyShareEntry{
				{Group: elliptic.X25519, KeyExchange: x25519Keypair.PublicKey},
				{Group: elliptic.X25519MLKEM768, KeyExchange: mlkemKeypair.PublicKey},
			},
		},
		&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
	})

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight2, nextFlight)
	assert.Equal(t, elliptic.X25519MLKEM768, state.SelectedGroup)
	assert.Nil(t, state.LocalKeypair)
	assert.Empty(t, state.KeyAgreementSecret)
}

func TestFlight13_0ParseRequestsPreferredGroupWhenShareMissing(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768, elliptic.X25519}

	x25519Keypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)

	state := newTestState13(t, false)
	cache := dtlsflight.NewCache()
	pushFlight13_0ClientHello(t, cache, cfg, []extension.Value{
		&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes)},
		&extension.SupportedGroups{Groups: cfg.EllipticCurves},
		&extension13.ClientKeyShare{
			Shares: []extension13.KeyShareEntry{
				{Group: elliptic.X25519, KeyExchange: x25519Keypair.PublicKey},
			},
		},
		&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
	})

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeTestContext13{
			state: state,
			cache: cache,
			cfg:   cfg,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight2, nextFlight)
	assert.Equal(t, elliptic.X25519MLKEM768, state.SelectedGroup)

	serverHello := serverHelloFromFlight13_2(t, state, cfg)
	keyShare, ok := findRetryKeyShare(serverHello.Extensions)
	require.True(t, ok)
	assert.Equal(t, elliptic.X25519MLKEM768, keyShare.SelectedGroup)
}

func TestFlight13_0ParseRejectsClientHelloWithSelectedSupportedVersion(t *testing.T) {
	cfg := testHandshakeConfig13(t)

	extensions := []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
	}
	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
	}
	clientHello.Extensions = extensions
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)

	parsed := &handshake.Handshake{}
	err = parsed.Unmarshal(rawClientHello)
	require.ErrorIs(t, err, dtlserrors.ErrInvalidSupportedVersionsFormat)
}

func pushFlight13_0ClientHello(
	t *testing.T,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
	exts []extension.Value,
) []byte {
	t.Helper()

	clientHello := &handshake.MessageClientHello{
		Version: protocol.Version1_2,
		Random:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		CipherSuiteIDs: []uint16{
			uint16(cfg.LocalCipherSuites[0].ID()),
		},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
	}
	clientHello.Extensions = exts
	rawClientHello, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	require.NoError(t, err)

	cache.Push(rawClientHello, cfg.InitialEpoch, 0, handshake.TypeClientHello, true)

	return rawClientHello
}

func requiredClientHello13Extensions(t *testing.T, cfg *dtlsconfig.HandshakeConfig) []extension.Value {
	t.Helper()

	clientKeypair, err := elliptic.GenerateKeypair(cfg.EllipticCurves[0])
	require.NoError(t, err)

	return []extension.Value{
		&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes)},
		&extension.SupportedGroups{Groups: cfg.EllipticCurves},
		&extension13.ClientKeyShare{
			Shares: []extension13.KeyShareEntry{
				{Group: clientKeypair.Curve, KeyExchange: clientKeypair.PublicKey},
			},
		},
		&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
	}
}

func TestFlight13_0ParseRequiresCertificateAuthClientHelloExtensions(t *testing.T) {
	t.Run("AcceptsSignatureAlgorithmsAndSupportedGroups", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(t, false)
		cache := dtlsflight.NewCache()
		pushFlight13_0ClientHello(t, cache, cfg, requiredClientHello13Extensions(t, cfg))

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeTestContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, dtlsflight13.Flight2, nextFlight)
		assert.Equal(t, cfg.LocalSignatureSchemes, state.RemoteSignatureSchemes)
		assert.Equal(t, cfg.EllipticCurves, state.RemoteGroups)
	})

	t.Run("RejectsPreSharedKeyWithoutModes", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(t, false)
		cache := dtlsflight.NewCache()
		binder := make([]byte, 32)
		pushFlight13_0ClientHello(t, cache, cfg, []extension.Value{
			&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
			&extension13.OfferedPSKs{
				Identities: []extension13.PSKIdentity{
					{Identity: []byte("psk"), ObfuscatedTicketAge: 0},
				},
				Binders: []extension13.PSKBinder{binder},
			},
		})

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeTestContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.ErrorIs(t, err, dtlserrors.ErrMissingPSKKeyExchangeModesExtension)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
		assert.Zero(t, nextFlight)
	})

	t.Run("RejectsMissingSignatureAlgorithms", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(t, false)
		cache := dtlsflight.NewCache()
		exts := requiredClientHello13Extensions(t, cfg)[1:]
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeTestContext13{
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
		state := newTestState13(t, false)
		cache := dtlsflight.NewCache()
		exts := requiredClientHello13Extensions(t, cfg)[1:]
		exts = append([]extension.Value{
			&extension.CertificateSignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes)},
		}, exts...)
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeTestContext13{
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
		state := newTestState13(t, false)
		cache := dtlsflight.NewCache()
		required := requiredClientHello13Extensions(t, cfg)
		exts := []extension.Value{required[0], required[2], required[3]}
		pushFlight13_0ClientHello(t, cache, cfg, exts)

		nextFlight, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight0, context.Background(), &handshakeTestContext13{
				state: state,
				cache: cache,
				cfg:   cfg,
			})

		require.ErrorIs(t, err, dtlserrors.ErrKeyShareWithoutSupportedGroups)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
		assert.Zero(t, nextFlight)
	})
}

func TestFlight13ServerParseAppendsNoHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.InsecureSkipHelloVerify = true
	state := newTestState13(t, false)
	cache := dtlsflight.NewCache()
	rawClientHello := pushFlight13_0ClientHello(t, cache, cfg, requiredClientHello13Extensions(t, cfg))
	clientHelloCanonical, err := canonicalHandshake13(rawClientHello)
	require.NoError(t, err)
	transcript := dtlshandshake.NewTranscript()

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight0, context.Background(), &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight4, nextFlight)
	assert.Equal(t, clientHelloCanonical, transcript.Bytes())
}

func TestFlight13ServerParseAppendsHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cookie := []byte{0xde, 0xad, 0xbe, 0xef}
	state := newTestState13(t, false)
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

	nextFlight, dtlsAlert, err := flight13ParseForTest(t, dtlsflight13.Flight0, context.Background(), flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight2, nextFlight)

	helloRetryRequest, dtlsAlert, err := flight13GenerateForTest(t, dtlsflight13.Flight2, flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, helloRetryRequest, 1)
	require.NoError(
		t, dtlshandshake.AppendOutboundHandshakeFlight(transcript, false, state.CipherSuite, helloRetryRequest),
	)
	helloRetryRequestCanonical := canonicalPacketHandshake13(t, helloRetryRequest[0])

	retry, err := negotiation.BuildClientHelloRetry(
		state.RemoteClientHelloSnapshots.Initial(), state.HelloRetryRequest, nil,
	)
	require.NoError(t, err)
	rawClientHello2, err := (&handshake.Handshake{
		Header: handshake.Header{MessageSequence: 1}, Message: retry,
	}).Marshal()
	require.NoError(t, err)
	cache.Push(rawClientHello2, 0, 1, handshake.TypeClientHello, true)
	clientHello2Canonical, err := canonicalHandshake13(rawClientHello2)
	require.NoError(t, err)

	nextFlight, dtlsAlert, err = flight13ParseForTest(t, dtlsflight13.Flight2, context.Background(), flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, dtlsflight13.Flight4, nextFlight)

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
	if state.SelectedGroup == 0 && state.Cookie == nil {
		state.Cookie = []byte{0x01}
	}
	pkts, dtlsAlert, err := flight13GenerateForTest(
		t, dtlsflight13.Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
	)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 1)

	require.NotNil(t, pkts[0].Content)

	content, ok := pkts[0].Content.(*handshake.Handshake)
	require.True(t, ok)

	serverHello, ok := content.Message.(*handshake.MessageServerHello)
	require.True(t, ok)

	return serverHello
}

func findSupportedVersions(exts []extension.Value) (*extension13.SelectedVersion, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension13.SelectedVersion); ok {
			return typed, true
		}
	}

	return nil, false
}

func findRetryKeyShare(exts []extension.Value) (*extension13.RetryKeyShare, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension13.RetryKeyShare); ok {
			return typed, true
		}
	}

	return nil, false
}

func findServerKeyShare(exts []extension.Value) (*extension13.ServerKeyShare, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension13.ServerKeyShare); ok {
			return typed, true
		}
	}

	return nil, false
}

func findCookie(exts []extension.Value) (*extension13.Cookie, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension13.Cookie); ok {
			return typed, true
		}
	}

	return nil, false
}

func TestFlight13_2Generate(t *testing.T) {
	t.Run("ServerHelloIsHelloRetryRequest", func(t *testing.T) {
		state := newTestState13(t, false)
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		assert.Equal(t, protocol.Version1_2, serverHello.Version)
		assert.Equal(t, [32]byte(handshake.HelloRetryRequestRandom()), serverHello.Random.MarshalFixed())
	})

	t.Run("ResetsHandshakeSendSequence", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(t, false)
		state.CipherSuite = cfg.LocalCipherSuites[0]
		state.HandshakeSendSequence = 7
		state.Cookie = []byte{0x01}

		_, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)

		assert.Equal(t, 0, state.HandshakeSendSequence)
	})

	t.Run("RejectsWithoutCipherSuite", func(t *testing.T) {
		state := newTestState13(t, false)
		cfg := testHandshakeConfig13(t)

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrCipherSuiteUnset)
		require.Nil(t, dtlsAlert)
		require.Nil(t, pkts)
	})

	t.Run("AlwaysIncludesSupportedVersions", func(t *testing.T) {
		state := newTestState13(t, false)
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		require.True(t, ok, "SupportedVersions extension must always be present")
		assert.Equal(t, protocol.Version1_3, supportedVersions.Version)
	})

	t.Run("IncludesCipherSuiteAndCompressionMethod", func(t *testing.T) {
		state := newTestState13(t, false)
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

	t.Run("RejectsHelloRetryRequestWithNoEffect", func(t *testing.T) {
		state := newTestState13(t, false)
		cfg := testHandshakeConfig13(t)
		state.CipherSuite = cfg.LocalCipherSuites[0]

		packets, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrInvalidHelloRetryRequest)
		require.Nil(t, dtlsAlert)
		require.Nil(t, packets)
	})

	t.Run("IncludesKeyShareWhenRemoteKeyEntriesPresent", func(t *testing.T) {
		state := newTestState13(t, false)
		state.SelectedGroup = elliptic.X25519
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		keyShare, ok := findRetryKeyShare(serverHello.Extensions)
		require.True(t, ok, "KeyShare must be present when remote key entries were offered")
		assert.Equal(t, elliptic.X25519, keyShare.SelectedGroup)
	})

	t.Run("OmitsKeyShareWhenSelectedGroupWasAlreadyOffered", func(t *testing.T) {
		state := newTestState13(t, false)
		state.SelectedGroup = elliptic.X25519
		state.RemoteKeyEntries = []extension13.KeyShareEntry{{
			Group:       elliptic.X25519,
			KeyExchange: []byte{0x01},
		}}
		state.HasRemoteKeyEntries = true
		state.Cookie = []byte{0x01}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		_, hasKeyShare := findRetryKeyShare(serverHello.Extensions)
		assert.False(t, hasKeyShare, "KeyShare must be omitted when the selected group was already offered")
	})

	t.Run("IncludesCookieWhenSet", func(t *testing.T) {
		cookie := []byte{0x01, 0x02, 0x03, 0x04}
		state := newTestState13(t, false)
		state.Cookie = cookie
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		cookieExt, ok := findCookie(serverHello.Extensions)
		require.True(t, ok, "Cookie must be present when set on state")
		assert.Equal(t, cookie, cookieExt.Cookie)
	})

	t.Run("IncludesAllExtensionsTogether", func(t *testing.T) {
		cookie := []byte{0xaa, 0xbb}
		state := newTestState13(t, false)
		state.SelectedGroup = elliptic.P256
		state.Cookie = cookie
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		require.Len(t, serverHello.Extensions, 3)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		require.True(t, ok)
		assert.Equal(t, protocol.Version1_3, supportedVersions.Version)

		keyShare, ok := findRetryKeyShare(serverHello.Extensions)
		require.True(t, ok)
		assert.Equal(t, elliptic.P256, keyShare.SelectedGroup)

		cookieExt, ok := findCookie(serverHello.Extensions)
		require.True(t, ok)
		assert.Equal(t, cookie, cookieExt.Cookie)
	})
}

func TestFlight13_4Generate(t *testing.T) {
	t.Run("RequestsClientCertificateWhenConfigured", func(t *testing.T) {
		certificate, err := selfsign.GenerateSelfSigned()
		require.NoError(t, err)
		keypair, err := elliptic.GenerateKeypair(testCurves13[0])
		require.NoError(t, err)

		tests := map[string]struct {
			clientAuth  dtlsconfig.ClientAuthType
			wantRequest bool
		}{
			"NoClientCert":               {clientAuth: dtlsconfig.NoClientCert},
			"RequestClientCert":          {clientAuth: dtlsconfig.RequestClientCert, wantRequest: true},
			"RequireAnyClientCert":       {clientAuth: dtlsconfig.RequireAnyClientCert, wantRequest: true},
			"VerifyClientCertIfGiven":    {clientAuth: dtlsconfig.VerifyClientCertIfGiven, wantRequest: true},
			"RequireAndVerifyClientCert": {clientAuth: dtlsconfig.RequireAndVerifyClientCert, wantRequest: true},
		}
		for name, test := range tests {
			t.Run(name, func(t *testing.T) {
				cfg := testHandshakeConfig13(t)
				cfg.LocalCertificates = []tls.Certificate{certificate}
				cfg.ClientAuth = test.clientAuth

				state := newTestState13(t, false)
				state.CipherSuite = cfg.LocalCipherSuites[0]
				state.LocalKeypair = keypair
				state.RemoteSignatureSchemes = append([]signaturehash.Algorithm(nil), cfg.LocalSignatureSchemes...)

				pkts, dtlsAlert, err := flight13GenerateForTest(
					t, dtlsflight13.Flight4, &handshakeTestContext13{state: state, cfg: cfg},
				)
				require.NoError(t, err)
				require.Nil(t, dtlsAlert)

				var certificateRequest *handshake.MessageCertificateRequest13
				for _, pkt := range pkts {
					handshakePacket, ok := pkt.Content.(*handshake.Handshake)
					if !ok {
						continue
					}
					request, ok := handshakePacket.Message.(*handshake.MessageCertificateRequest13)
					if !ok {
						continue
					}
					require.Nil(t, certificateRequest, "server flight contains multiple CertificateRequest messages")
					certificateRequest = request
					assert.Equal(t, dtlsflight13.EpochHandshake, pkt.Epoch)
					assert.True(t, pkt.Protection == dtlsflight.ProtectionCiphertext)
				}

				if !test.wantRequest {
					assert.Nil(t, certificateRequest)

					return
				}

				require.NotNil(t, certificateRequest)
				assert.Empty(t, certificateRequest.CertificateRequestContext)
				require.Len(t, certificateRequest.Extensions, 1)
				signatureAlgorithms, ok := certificateRequest.Extensions[0].(*extension.SignatureAlgorithms)
				require.True(t, ok)
				assert.Equal(t, dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes), signatureAlgorithms.Schemes)
			})
		}
	})

	t.Run("GeneratesCertificateAuthenticatedServerFlight", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		certificate, err := selfsign.GenerateSelfSigned()
		require.NoError(t, err)
		cfg.LocalCertificates = []tls.Certificate{certificate}
		group := cfg.EllipticCurves[0]
		keypair, err := elliptic.GenerateKeypair(group)
		require.NoError(t, err)

		state := newTestState13(t, false)
		state.CipherSuite = cfg.LocalCipherSuites[0]
		state.LocalKeypair = keypair
		state.RemoteSignatureSchemes = append([]signaturehash.Algorithm(nil), cfg.LocalSignatureSchemes...)
		state.LocalRandom = handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01, 0x02, 0x03}}

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight4, &handshakeTestContext13{state: state, cfg: cfg},
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		require.Len(t, pkts, 5)
		assert.Equal(t, uint16(0), pkts[0].Epoch)
		assert.False(t, pkts[0].Protection == dtlsflight.ProtectionCiphertext)

		serverHelloHandshake, ok := pkts[0].Content.(*handshake.Handshake)
		require.True(t, ok)
		serverHello, ok := serverHelloHandshake.Message.(*handshake.MessageServerHello)
		require.True(t, ok)
		assert.Equal(t, protocol.Version1_2, serverHello.Version)
		assert.Equal(t, state.LocalRandom, serverHello.Random)
		require.NotNil(t, serverHello.CipherSuiteID)
		assert.Equal(t, uint16(cfg.LocalCipherSuites[0].ID()), *serverHello.CipherSuiteID)

		keyShare, ok := findServerKeyShare(serverHello.Extensions)
		require.True(t, ok)
		assert.Equal(t, group, keyShare.Share.Group)
		assert.Equal(t, keypair.PublicKey, keyShare.Share.KeyExchange)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		require.True(t, ok)
		assert.Equal(t, protocol.Version1_3, supportedVersions.Version)

		encryptedExtensionsHandshake, ok := pkts[1].Content.(*handshake.Handshake)
		require.True(t, ok)
		assert.Equal(t, dtlsflight13.EpochHandshake, pkts[1].Epoch)
		assert.True(t, pkts[1].Protection == dtlsflight.ProtectionCiphertext)
		encryptedExtensions, ok := encryptedExtensionsHandshake.Message.(*handshake.MessageEncryptedExtensions)
		require.True(t, ok)
		assert.Empty(t, encryptedExtensions.Extensions)

		certificateHandshake, ok := pkts[2].Content.(*handshake.Handshake)
		require.True(t, ok)
		assert.Equal(t, dtlsflight13.EpochHandshake, pkts[2].Epoch)
		assert.True(t, pkts[2].Protection == dtlsflight.ProtectionCiphertext)
		certificateMessage, ok := certificateHandshake.Message.(*handshake.MessageCertificate13)
		require.True(t, ok)
		assert.Empty(t, certificateMessage.CertificateRequestContext)
		require.Len(t, certificateMessage.CertificateList, len(certificate.Certificate))

		certificateVerifyHandshake, ok := pkts[3].Content.(*handshake.Handshake)
		require.True(t, ok)
		assert.Equal(t, dtlsflight13.EpochHandshake, pkts[3].Epoch)
		assert.True(t, pkts[3].Protection == dtlsflight.ProtectionCiphertext)
		certificateVerify, ok := certificateVerifyHandshake.Message.(*handshake.MessageCertificateVerify)
		require.True(t, ok)
		assert.Empty(t, certificateVerify.Signature)
		assert.NotNil(t, pkts[3].CertificateVerifySigner)

		finishedHandshake, ok := pkts[4].Content.(*handshake.Handshake)
		require.True(t, ok)
		assert.Equal(t, dtlsflight13.EpochHandshake, pkts[4].Epoch)
		assert.True(t, pkts[4].Protection == dtlsflight.ProtectionCiphertext)
		_, ok = finishedHandshake.Message.(*handshake.MessageFinished)
		require.True(t, ok)
	})

	t.Run("RejectsWithoutCipherSuite", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(t, false)

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight4, &handshakeTestContext13{state: state, cfg: cfg},
		)
		require.ErrorIs(t, err, dtlserrors.ErrCipherSuiteUnset)
		require.Nil(t, dtlsAlert)
		require.Nil(t, pkts)
	})

	t.Run("RejectsWithoutLocalKeypair", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := newTestState13(t, false)
		state.CipherSuite = cfg.LocalCipherSuites[0]

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, dtlsflight13.Flight4, &handshakeTestContext13{state: state, cfg: cfg},
		)
		require.ErrorIs(t, err, dtlserrors.ErrServerKeyShareMissing)
		require.Nil(t, dtlsAlert)
		require.Nil(t, pkts)
	})
}

func pushClientHello13(
	t *testing.T,
	cache *dtlsflight.Cache,
	version protocol.Version,
	exts []extension.Value,
) {
	t.Helper()

	pushClientHello13WithSequence(t, cache, version, 0, exts)
}

func pushClientHello13WithSequence(
	t *testing.T,
	cache *dtlsflight.Cache,
	version protocol.Version,
	seq uint16,
	exts []extension.Value,
) []byte {
	t.Helper()

	content := &handshake.Handshake{
		Header: handshake.Header{MessageSequence: seq},
		Message: withExtensions(&handshake.MessageClientHello{
			Version:            version,
			Random:             handshake.Random{},
			CipherSuiteIDs:     []uint16{uint16(ciphersuite.TLS_AES_128_GCM_SHA256)},
			CompressionMethods: dtlsflight.DefaultCompressionMethods(),
		}, exts),
	}

	raw, err := content.Marshal()
	require.NoError(t, err)

	cache.Push(raw, 0, seq, handshake.TypeClientHello, true)

	return raw
}

func flight13_2Context(
	state *dtlsstate.State13, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig,
) *handshakeTestContext13 {
	seedFlight13RetryRequest(state, cache, cfg)

	return &handshakeTestContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: dtlshandshake.NewTranscript(),
	}
}

func seedFlight13RetryRequest(
	state *dtlsstate.State13,
	cache *dtlsflight.Cache,
	cfg *dtlsconfig.HandshakeConfig,
) {
	if request := state.HelloRetryRequest; request.HasCookie || request.HasSelectedGroup {
		return
	}
	pull := cache.FullPullMapItems(state.HandshakeRecvSequence, state.CipherSuite,
		dtlsflight.HandshakeCachePullRule{
			Typ: handshake.TypeClientHello, Epoch: cfg.InitialEpoch, IsClient: true,
		})
	retry, ok := pull.Messages[handshake.TypeClientHello].(*handshake.MessageClientHello)
	if pull.Err != nil || !pull.Ready || !ok {
		return
	}
	clientHello := *retry
	clientHello.Extensions = slices.DeleteFunc(slices.Clone(retry.Extensions), func(value extension.Value) bool {
		return value.ExtensionType() == extension.TypeCookie
	})
	_, initial, err := negotiation.FinalizeClientHello(&clientHello, nil)
	if err != nil {
		return
	}
	state.RemoteClientHelloSnapshots.Reset()
	if recordErr := state.RemoteClientHelloSnapshots.Record(initial); recordErr != nil {
		return
	}
	id := uint16(cfg.LocalCipherSuites[0].ID())
	extensions := []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
		&extension13.Cookie{Cookie: state.Cookie},
	}
	request, err := negotiation.ValidateHelloRetryRequest(initial, withExtensions(&handshake.MessageServerHello{
		CipherSuiteID: &id,
	}, extensions))
	if err == nil {
		state.HelloRetryRequest = request
	}
}

func TestFlight13_2Parse(t *testing.T) {
	cookie := []byte{0xde, 0xad, 0xbe, 0xef}

	t.Run("AdvancesToFlight4OnMatchingCookie", func(t *testing.T) {
		state := newTestState13(t, false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension13.Cookie{Cookie: cookie})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, dtlsflight13.Flight4, next)
		assert.Equal(t, 1, state.HandshakeRecvSequence)
	})

	t.Run("GeneratesX25519MLKEM768KeypairAfterMatchingCookie", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768}
		clientKeypair, err := elliptic.GenerateKeypair(elliptic.X25519MLKEM768)
		require.NoError(t, err)

		state := newTestState13(t, false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		pushClientHello13(t, cache, protocol.Version1_2, []extension.Value{
			&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes)},
			&extension.SupportedGroups{Groups: cfg.EllipticCurves},
			&extension13.ClientKeyShare{
				Shares: []extension13.KeyShareEntry{
					{Group: elliptic.X25519MLKEM768, KeyExchange: clientKeypair.PublicKey},
				},
			},
			&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
			&extension13.Cookie{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, dtlsflight13.Flight4, next)
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

		state := newTestState13(t, false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		pushClientHello13(t, cache, protocol.Version1_2, []extension.Value{
			&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(cfg.LocalSignatureSchemes)},
			&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.P384}},
			&extension13.ClientKeyShare{
				Shares: []extension13.KeyShareEntry{
					{Group: elliptic.P384, KeyExchange: clientKeypair.PublicKey},
				},
			},
			&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
			&extension13.Cookie{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrNoSupportedEllipticCurves)
		assert.Equal(t, dtlsflight13.Flight(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, dtlsAlert)
		assert.Empty(t, state.KeyAgreementSecret)
		assert.Nil(t, state.LocalKeypair)
		assert.Zero(t, state.SelectedGroup)
		assert.False(t, state.RemoteClientHelloSnapshots.Current().Offered(extension.TypeCookie))
	})

	t.Run("KeepsWaitingWhenNoClientHelloCached", func(t *testing.T) {
		state := newTestState13(t, false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		assert.Equal(t, dtlsflight13.Flight(0), next)
		assert.Equal(t, 0, state.HandshakeRecvSequence)
	})

	t.Run("RejectsMissingCookie", func(t *testing.T) {
		state := newTestState13(t, false)
		state.Cookie = cookie
		state.ServerName = "original.example"
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension.ServerNameOffer{ServerName: "poison.example"})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrCookieMismatch)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlsAlert)
		assert.Equal(t, dtlsflight13.Flight(0), next)
		assert.Equal(t, 0, state.HandshakeRecvSequence)
		assert.Equal(t, "original.example", state.ServerName)
		assert.Empty(t, state.RemoteSignatureSchemes)
		assert.Empty(t, state.RemoteGroups)
	})

	t.Run("RejectsCookieMismatch", func(t *testing.T) {
		state := newTestState13(t, false)
		state.Cookie = cookie
		state.ServerName = "original.example"
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		exts := append(requiredClientHello13Extensions(t, cfg), &extension.ServerNameOffer{ServerName: "poison.example"},
			&extension13.Cookie{Cookie: []byte{0x00, 0x01, 0x02, 0x03}})
		pushClientHello13(t, cache, protocol.Version1_2, exts)

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrCookieMismatch)
		assert.Equal(t, dtlsflight13.Flight(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlsAlert)
		assert.Equal(t, 0, state.HandshakeRecvSequence)
		assert.Equal(t, "original.example", state.ServerName)
		assert.Empty(t, state.RemoteSignatureSchemes)
		assert.Empty(t, state.RemoteGroups)
	})

	t.Run("RejectsUnsupportedVersion", func(t *testing.T) {
		state := newTestState13(t, false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version{Major: 0xfe, Minor: 0xfd - 1}, []extension.Value{
			&extension13.Cookie{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrUnsupportedProtocolVersion)
		assert.Equal(t, dtlsflight13.Flight(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.ProtocolVersion}, dtlsAlert)
	})

	t.Run("RejectsMissingCertificateAuthExtensions", func(t *testing.T) {
		state := newTestState13(t, false)
		state.Cookie = cookie
		cache := dtlsflight.NewCache()
		cfg := testHandshakeConfig13(t)

		pushClientHello13(t, cache, protocol.Version1_2, []extension.Value{
			&extension13.Cookie{Cookie: cookie},
		})

		next, dtlsAlert, err := flight13ParseForTest(
			t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrMissingClientHelloExtension)
		assert.Equal(t, dtlsflight13.Flight(0), next)
		require.NotNil(t, dtlsAlert)
		assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension}, dtlsAlert)
	})
}

func findConnectionID(exts []extension.Value) (*extension.ConnectionID, bool) {
	for _, ext := range exts {
		if typed, ok := ext.(*extension.ConnectionID); ok {
			return typed, true
		}
	}

	return nil, false
}

func clientHello13SnapshotHistory(t *testing.T, extensions []extension.Value) (history negotiation.ClientHelloSnapshots) { //nolint:lll
	t.Helper()
	_, snapshot, err := negotiation.FinalizeClientHello(withExtensions(&handshake.MessageClientHello{ //nolint:lll
		Version: protocol.Version1_2, CipherSuiteIDs: []uint16{uint16(ciphersuite.TLS_AES_128_GCM_SHA256)},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
	}, extensions), nil)
	require.NoError(t, err)
	require.NoError(t, history.Record(snapshot))

	return history
}

func assertSnapshotConnectionID(t *testing.T, snapshot negotiation.ClientHelloSnapshot, expectedCID []byte, expectedPresent bool) { //nolint:lll
	t.Helper()
	cid, present := negotiation.ConnectionIDOffer(snapshot)
	assert.Equal(t, expectedPresent, present)
	assert.True(t, bytes.Equal(expectedCID, cid))
}

func assertConnectionIDValue(t *testing.T, expected, actual []byte) {
	t.Helper()
	assert.True(t, bytes.Equal(expected, actual))
}

func assertConnectionIDs(t *testing.T, state *dtlsstate.State13, localCID, remoteCID []byte, negotiated bool) {
	t.Helper()
	assert.Equal(t, [3]bool{negotiated, negotiated, negotiated},
		[3]bool{state.LocalCIDOffered, state.RemoteCIDOffered, state.CID.Negotiated})
	assertConnectionIDValue(t, localCID, state.LocalConnectionID())
	assertConnectionIDValue(t, remoteCID, state.RemoteConnectionID)
	if !negotiated {
		assert.Zero(t, state.CID)

		return
	}
	assertConnectionIDValue(t, localCID, state.LocalConnectionIDForInboundRecords())
	assert.Equal(t, len(localCID), state.CID.Receive.Length)
	assert.Equal(t, len(localCID) > 0, state.CID.Receive.Expected)
	assert.Equal(t, len(localCID) > 0, state.CID.Receive.CanSendNewConnectionID)
	assert.Equal(t, len(remoteCID) > 0, state.CID.Send.UseCID)
	assertConnectionIDValue(t, remoteCID, state.CID.Send.Active)
}

func clientHelloFromFlight13Packet(t *testing.T, packet *dtlsflight.Outbound) *handshake.MessageClientHello {
	t.Helper()

	hand, ok := packet.Content.(*handshake.Handshake)
	require.True(t, ok)
	raw, err := hand.Marshal()
	require.NoError(t, err)

	var parsed handshake.Handshake
	require.NoError(t, parsed.Unmarshal(raw))
	clientHello, ok := parsed.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	return clientHello
}

func setConnectionIDs(clientHello *handshake.MessageClientHello, cids ...[]byte) {
	extensions := clientHello.Extensions[:0]
	for _, ext := range clientHello.Extensions {
		_, isConnectionID := ext.(*extension.ConnectionID)
		_, isRRC := ext.(*extension.ReturnRoutabilityCheck)
		if !isConnectionID && (!isRRC || len(cids) != 0) {
			extensions = append(extensions, ext)
		}
	}
	for _, cid := range cids {
		extensions = append(extensions, &extension.ConnectionID{CID: cid})
	}
	clientHello.Extensions = extensions
}

type connectionIDNegotiationCase struct {
	clientCID    []byte
	serverCIDs   [][]byte
	clientOffers bool
	expectedErr  error
	description  alert.Description
}

func connectionIDNegotiationCases() map[string]connectionIDNegotiationCase {
	return map[string]connectionIDNegotiationCase{
		"ServerDeclinesEmpty":    {clientOffers: true},
		"ServerDeclinesNonEmpty": {clientOffers: true, clientCID: []byte{1}},
		"BothEmpty":              {clientOffers: true, serverCIDs: [][]byte{{}}},
		"OnlyClientSendsCID":     {clientOffers: true, serverCIDs: [][]byte{{0x10, 0x11}}},
		"OnlyServerSendsCID":     {clientOffers: true, clientCID: []byte{1, 2}, serverCIDs: [][]byte{{}}},
		"Bidirectional":          {clientOffers: true, clientCID: []byte{1, 2}, serverCIDs: [][]byte{{0x10, 0x11}}},
	}
}

func TestFlight13_1GenerateConnectionIDOffer(t *testing.T) {
	tests := map[string]struct {
		generated, expected []byte
		hooked              [][]byte
		generator, hook     bool
		invalid             bool
	}{
		"Disabled":      {},
		"Empty":         {generator: true},
		"NonEmpty":      {generated: []byte{1, 2, 3, 4}, expected: []byte{1, 2, 3, 4}, generator: true},
		"HookRemove":    {generated: []byte{1, 2}, generator: true, hook: true},
		"HookReplace":   {generated: []byte{1, 2}, expected: []byte{0xaa, 0xbb}, hooked: [][]byte{{0xaa, 0xbb}}, generator: true, hook: true}, //nolint:lll
		"HookAdd":       {expected: []byte{0xcc}, hooked: [][]byte{{0xcc}}, hook: true},
		"HookDuplicate": {generated: []byte{1}, hooked: [][]byte{{1}, {2}}, generator: true, hook: true, invalid: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, calls := testHandshakeConfig13(t), 0
			cfg.EnableRRC = true
			if test.generator {
				cfg.ConnectionIDGenerator = func() []byte {
					calls++

					return test.generated
				}
			}
			if test.hook {
				cfg.ClientHelloMessageHook = func(ch handshake.MessageClientHello) handshake.Message {
					setConnectionIDs(&ch, test.hooked...)

					return &ch
				}
			}
			state := newTestState13(t, true)
			if test.invalid {
				state.LocalClientHelloSnapshots.Reset()
			}
			packets, dtlsAlert, err := flight13GenerateForTest(
				t, dtlsflight13.Flight1, &handshakeTestContext13{state: state, cfg: cfg},
			)
			if test.invalid {
				require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
				assert.Nil(t, dtlsAlert)
				assert.Nil(t, packets)
				assert.False(t, state.LocalClientHelloSnapshots.Current().Valid())
			} else {
				require.NoError(t, err)
				require.Nil(t, dtlsAlert)
				require.Len(t, packets, 1)
				clientHelloExtensions := clientHelloFromFlight13Packet(t, packets[0]).Extensions
				cid, present := findConnectionID(clientHelloExtensions)
				expectedPresent := test.generator
				if test.hook {
					expectedPresent = len(test.hooked) == 1
				}
				assert.Equal(t, expectedPresent, present)
				rrcPresent := slices.ContainsFunc(clientHelloExtensions, func(value extension.Value) bool {
					return value.ExtensionType() == extension.TypeReturnRoutabilityCheck
				})
				assert.Equal(t, test.generator && expectedPresent, rrcPresent)
				assertSnapshotConnectionID(t, state.LocalClientHelloSnapshots.Current(), test.expected, present)
				assertConnectionIDValue(t, test.expected, state.LocalConnectionIDForInboundRecords())
				if present {
					require.NotNil(t, cid)
					assertConnectionIDValue(t, test.expected, cid.CID)
				}
			}
			assert.Equal(t, test.generator, calls == 1)
			assertConnectionIDs(t, state, nil, nil, false)
		})
	}
}

func TestFlight13_3GenerateConnectionIDOffer(t *testing.T) { //nolint:cyclop // Compact scenario table.
	tests := map[string]struct {
		generated, expected  []byte
		retryCIDs            [][]byte
		generator, hookAll   bool
		mutateRetry, invalid bool
	}{
		"ReuseEmpty":      {generator: true},
		"ReuseNonEmpty":   {generated: []byte{1, 2, 3, 4}, expected: []byte{1, 2, 3, 4}, generator: true},
		"ReuseHookOnly":   {expected: []byte{0xcc}, retryCIDs: [][]byte{{0xcc}}, hookAll: true},
		"RejectRemove":    {generated: []byte{1}, generator: true, mutateRetry: true, invalid: true},
		"RejectReplace":   {generated: []byte{1}, retryCIDs: [][]byte{{0xff}}, generator: true, mutateRetry: true, invalid: true}, //nolint:lll
		"RejectAdd":       {retryCIDs: [][]byte{{0xff}}, mutateRetry: true, invalid: true},
		"RejectDuplicate": {generated: []byte{1}, retryCIDs: [][]byte{{1}, {1}}, generator: true, mutateRetry: true, invalid: true}, //nolint:lll
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, generatorCalls, hookCalls := testHandshakeConfig13(t), 0, 0
			if test.generator {
				cfg.ConnectionIDGenerator = func() []byte {
					generatorCalls++
					if generatorCalls == 1 {
						return test.generated
					}

					return []byte{0xff}
				}
			}
			if test.hookAll || test.mutateRetry {
				cfg.ClientHelloMessageHook = func(ch handshake.MessageClientHello) handshake.Message {
					hookCalls++
					if test.hookAll || hookCalls == 2 {
						setConnectionIDs(&ch, test.retryCIDs...)
					}

					return &ch
				}
			}
			state := newTestState13(t, true)
			firstFlight, dtlsAlert, err := flight13GenerateForTest(
				t, dtlsflight13.Flight1, &handshakeTestContext13{state: state, cfg: cfg},
			)
			require.NoError(t, err)
			require.Nil(t, dtlsAlert)
			require.Len(t, firstFlight, 1)
			initialSnapshot := state.LocalClientHelloSnapshots.Current()
			state.RemoteVersions, state.Cookie = []protocol.Version{protocol.Version1_3}, []byte{0xaa}
			state.HelloRetryRequest = retryRequestForTest(t, state, cfg, initialSnapshot, 0)

			secondFlight, dtlsAlert, err := flight13GenerateForTest(
				t, dtlsflight13.Flight3, &handshakeTestContext13{state: state, cfg: cfg},
			)
			assert.Equal(t, test.generator, generatorCalls == 1)
			if test.hookAll || test.mutateRetry {
				assert.Equal(t, 2, hookCalls)
			}
			if test.invalid {
				require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
				assert.Nil(t, dtlsAlert)
				assert.Nil(t, secondFlight)
				assertSnapshotConnectionID(t, initialSnapshot, test.generated, test.generator)
				assertSnapshotConnectionID(t, state.LocalClientHelloSnapshots.Current(), test.generated, test.generator)
			} else {
				require.NoError(t, err)
				require.Nil(t, dtlsAlert)
				require.Len(t, secondFlight, 1)
				firstCID, firstPresent := findConnectionID(clientHelloFromFlight13Packet(t, firstFlight[0]).Extensions)
				secondCID, secondPresent := findConnectionID(clientHelloFromFlight13Packet(t, secondFlight[0]).Extensions)
				require.True(t, firstPresent)
				require.True(t, secondPresent)
				assert.Equal(t, firstCID.CID, secondCID.CID)
				assertConnectionIDValue(t, test.expected, secondCID.CID)
				assertSnapshotConnectionID(t, state.LocalClientHelloSnapshots.Current(), test.expected, true)
			}
			assertConnectionIDs(t, state, nil, nil, false)
		})
	}
}

func TestFlight13_2ParseConnectionIDOffer(t *testing.T) {
	cookie := []byte{0xde, 0xad, 0xbe, 0xef}
	tests := map[string]struct {
		firstPresent bool
		firstCID     []byte
		secondCIDs   [][]byte
		expectedErr  error
	}{
		"RejectRemovedEmpty": {firstPresent: true, firstCID: []byte{}, expectedErr: dtlserrors.ErrInvalidClientHello},
		"RejectAddedEmpty":   {secondCIDs: [][]byte{{}}, expectedErr: dtlserrors.ErrInvalidClientHello},
		"RejectChangedValue": {firstPresent: true, firstCID: []byte{1}, secondCIDs: [][]byte{{2}}, expectedErr: dtlserrors.ErrInvalidClientHello},      //nolint:lll
		"RejectDuplicate":    {firstPresent: true, firstCID: []byte{1}, secondCIDs: [][]byte{{1}, {1}}, expectedErr: dtlserrors.ErrDuplicateExtension}, //nolint:lll
		"RepeatEmpty":        {firstPresent: true, firstCID: []byte{}, secondCIDs: [][]byte{{}}},
		"RepeatNonEmpty":     {firstPresent: true, firstCID: []byte{1, 2}, secondCIDs: [][]byte{{1, 2}}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := testHandshakeConfig13(t)
			state := newTestState13(t, false)
			state.Cookie = cookie
			initialExtensions := requiredClientHello13Extensions(t, cfg)
			if test.firstPresent {
				initialExtensions = append(initialExtensions, &extension.ConnectionID{CID: test.firstCID})
			}
			state.RemoteClientHelloSnapshots = clientHello13SnapshotHistory(t, initialExtensions)
			state.HelloRetryRequest = retryRequestForTest(
				t, state, cfg, state.RemoteClientHelloSnapshots.Initial(), 0,
			)
			cache := dtlsflight.NewCache()
			initial, err := negotiation.ClientHelloFromSnapshot(state.RemoteClientHelloSnapshots.Initial())
			require.NoError(t, err)
			exts := slices.DeleteFunc(slices.Clone(initial.Extensions), func(value extension.Value) bool {
				return value.ExtensionType() == extension.TypeConnectionID
			})
			for _, cid := range test.secondCIDs {
				exts = append(exts, &extension.ConnectionID{CID: cid})
			}
			exts = append(exts, &extension13.Cookie{Cookie: cookie})
			pushClientHello13(t, cache, protocol.Version1_2, exts)

			nextFlight, dtlsAlert, err := flight13ParseForTest(
				t, dtlsflight13.Flight2, context.Background(), flight13_2Context(state, cache, cfg),
			)

			if test.expectedErr != nil {
				require.ErrorIs(t, err, test.expectedErr)
				assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlsAlert)
				assert.Zero(t, nextFlight)
				assert.Nil(t, state.LocalKeypair)
			} else {
				require.NoError(t, err)
				require.Nil(t, dtlsAlert)
				assert.Equal(t, dtlsflight13.Flight4, nextFlight)
			}
			assertSnapshotConnectionID(
				t, state.RemoteClientHelloSnapshots.Current(), test.firstCID, test.firstPresent,
			)
			assertConnectionIDs(t, state, nil, nil, false)
		})
	}
}

func TestFlight13_4GenerateNegotiatesConnectionIDs(t *testing.T) { //nolint:cyclop // Compact scenario matrix.
	tests := connectionIDNegotiationCases()
	tests["NoClientOffer"] = connectionIDNegotiationCase{serverCIDs: [][]byte{{0x10}}}
	tests["InvalidServerCID"] = connectionIDNegotiationCase{clientOffers: true, serverCIDs: [][]byte{make([]byte, 256)}} //nolint:lll
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var serverCID []byte
			if len(test.serverCIDs) > 0 {
				serverCID = test.serverCIDs[0]
			}
			cfg := testHandshakeConfig13(t)
			cfg.EnableRRC = true
			certificate, err := selfsign.GenerateSelfSigned()
			require.NoError(t, err)
			cfg.LocalCertificates = []tls.Certificate{certificate}
			generatorCalls := 0
			if len(test.serverCIDs) > 0 {
				cfg.ConnectionIDGenerator = func() []byte {
					generatorCalls++

					return serverCID
				}
			}
			keypair, err := elliptic.GenerateKeypair(cfg.EllipticCurves[0])
			require.NoError(t, err)
			state := newTestState13(t, false)
			state.CipherSuite = cfg.LocalCipherSuites[0]
			state.LocalKeypair = keypair
			state.RemoteSignatureSchemes = append([]signaturehash.Algorithm(nil), cfg.LocalSignatureSchemes...)
			offerExtensions := requiredClientHello13Extensions(t, cfg)
			if test.clientOffers {
				offerExtensions = append(
					offerExtensions,
					&extension.ConnectionID{CID: test.clientCID},
					&extension.ReturnRoutabilityCheck{},
				)
			}
			state.RemoteClientHelloSnapshots = clientHello13SnapshotHistory(t, offerExtensions)

			if len(serverCID) > 255 {
				packets, dtlsAlert, err := flight13GenerateForTest(
					t, dtlsflight13.Flight4, &handshakeTestContext13{state: state, cfg: cfg},
				)
				require.ErrorIs(t, err, dtlserrors.ErrInvalidCIDFormat)
				assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, dtlsAlert)
				assert.Nil(t, packets)
				assert.Equal(t, 1, generatorCalls)
				assertConnectionIDs(t, state, nil, nil, false)

				return
			}

			expectedNegotiated := test.clientOffers && len(test.serverCIDs) > 0
			for range 2 {
				packets, dtlsAlert, err := flight13GenerateForTest(
					t, dtlsflight13.Flight4, &handshakeTestContext13{state: state, cfg: cfg},
				)
				require.NoError(t, err)
				require.Nil(t, dtlsAlert)
				require.NotEmpty(t, packets)
				serverHelloHandshake, ok := packets[0].Content.(*handshake.Handshake)
				require.True(t, ok)
				serverHello, ok := serverHelloHandshake.Message.(*handshake.MessageServerHello)
				require.True(t, ok)
				connectionID, present := findConnectionID(serverHello.Extensions)
				assert.Equal(t, expectedNegotiated, present)
				assert.Equal(t, expectedNegotiated, state.CID.Negotiated)
				assert.Equal(t, expectedNegotiated, state.RRCNegotiated)
				if expectedNegotiated {
					require.NotNil(t, connectionID)
					if len(serverCID) == 0 {
						assert.Empty(t, connectionID.CID)
					} else {
						assert.Equal(t, serverCID, connectionID.CID)
					}
				}
			}
			assertSnapshotConnectionID(
				t, state.RemoteClientHelloSnapshots.Current(), test.clientCID, test.clientOffers,
			)
			if !expectedNegotiated {
				assert.Zero(t, generatorCalls)
				assertConnectionIDs(t, state, nil, nil, false)

				return
			}

			assert.Equal(t, 1, generatorCalls)
			assertConnectionIDs(t, state, serverCID, test.clientCID, true)
		})
	}
}

func TestFlight13_0ParseConnectionIDOffer(t *testing.T) {
	tests := map[string]struct {
		cids     [][]byte
		expected []byte
		invalid  bool
	}{
		"Absent":    {},
		"Empty":     {cids: [][]byte{{}}},
		"NonEmpty":  {cids: [][]byte{{1, 2, 3, 4}}, expected: []byte{1, 2, 3, 4}},
		"Duplicate": {cids: [][]byte{{1}, {2}}, invalid: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := testHandshakeConfig13(t)
			generatorCalls := 0
			cfg.ConnectionIDGenerator = func() []byte {
				generatorCalls++

				return []byte{0xaa}
			}
			state := newTestState13(t, false)
			if test.invalid {
				state.RemoteClientHelloSnapshots.Reset()
			}
			cache := dtlsflight.NewCache()
			exts := requiredClientHello13Extensions(t, cfg)
			for _, cid := range test.cids {
				exts = append(exts, &extension.ConnectionID{CID: cid})
			}
			pushFlight13_0ClientHello(t, cache, cfg, exts)

			nextFlight, dtlsAlert, err := flight13ParseForTest(
				t, dtlsflight13.Flight0, context.Background(), &handshakeTestContext13{
					state: state,
					cache: cache,
					cfg:   cfg,
				},
			)
			if test.invalid {
				require.ErrorIs(t, err, dtlserrors.ErrDuplicateExtension)
				assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlsAlert)
				assert.Zero(t, nextFlight)
				assert.False(t, state.RemoteClientHelloSnapshots.Current().Valid())
			} else {
				require.NoError(t, err)
				require.Nil(t, dtlsAlert)
				assert.Equal(t, dtlsflight13.Flight2, nextFlight)
				present := len(test.cids) == 1
				assertSnapshotConnectionID(t, state.RemoteClientHelloSnapshots.Current(), test.expected, present)
			}
			assert.Zero(t, generatorCalls, "server CID generation is deferred until the final ServerHello")
			assertConnectionIDs(t, state, nil, nil, false)
		})
	}
}

func parseFlight13ServerHelloConnectionID(
	t *testing.T,
	clientOffers bool,
	clientCID []byte,
	serverCIDs [][]byte,
) (*dtlsstate.State13, dtlsflight13.Flight, *alert.Alert, error) {
	t.Helper()

	cfg := testHandshakeConfig13(t)
	if clientOffers {
		cfg.ConnectionIDGenerator = func() []byte {
			return clientCID
		}
	}
	state := newTestState13(t, true)
	transcript := dtlshandshake.NewTranscript()
	clientHello, dtlsAlert, err := flight13GenerateForTest(
		t, dtlsflight13.Flight1, &handshakeTestContext13{state: state, cfg: cfg},
	)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	appended, err := dtlshandshake.AppendClientHelloInitialFlights(transcript, clientHello)
	require.NoError(t, err)
	require.True(t, appended)

	group := cfg.EllipticCurves[0]
	serverKeypair, err := elliptic.GenerateKeypair(group)
	require.NoError(t, err)
	extensions := []extension.Value{
		&extension13.SelectedVersion{Version: protocol.Version1_3},
		&extension13.ServerKeyShare{Share: extension13.KeyShareEntry{
			Group: group, KeyExchange: serverKeypair.PublicKey,
		}},
	}
	for _, cid := range serverCIDs {
		extensions = append(extensions, &extension.ConnectionID{CID: cid})
	}
	rawServerHello := marshalServerHello(t, cfg, handshake.Random{
		RandomBytes: [handshake.RandomBytesLength]byte{0x01},
	}, extensions)
	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

	nextFlight, dtlsAlert, err := flight13ParseForTest(
		t, dtlsflight13.Flight3, context.Background(), &handshakeTestContext13{
			state:      state,
			cache:      cache,
			cfg:        cfg,
			transcript: transcript,
		},
	)

	return state, nextFlight, dtlsAlert, err
}

func TestFlight13_3ParseConnectionID(t *testing.T) {
	tests := connectionIDNegotiationCases()
	tests["UnsolicitedEmpty"] = connectionIDNegotiationCase{serverCIDs: [][]byte{{}}, expectedErr: dtlserrors.ErrUnsolicitedExtension, description: alert.UnsupportedExtension}                                          //nolint:lll
	tests["UnsolicitedNonEmpty"] = connectionIDNegotiationCase{serverCIDs: [][]byte{{0x10, 0x11}}, expectedErr: dtlserrors.ErrUnsolicitedExtension, description: alert.UnsupportedExtension}                             //nolint:lll
	tests["Duplicate"] = connectionIDNegotiationCase{clientOffers: true, clientCID: []byte{1}, serverCIDs: [][]byte{{0x10}, {0x11}}, expectedErr: dtlserrors.ErrDuplicateExtension, description: alert.IllegalParameter} //nolint:lll

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			state, nextFlight, dtlsAlert, err := parseFlight13ServerHelloConnectionID(
				t, test.clientOffers, test.clientCID, test.serverCIDs,
			)
			assert.Zero(t, nextFlight, "the parser should wait for the protected remainder of Flight 3")
			if test.expectedErr != nil {
				require.ErrorIs(t, err, test.expectedErr)
				assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: test.description}, dtlsAlert)
				assertConnectionIDs(t, state, nil, nil, false)

				return
			}
			require.NoError(t, err)
			require.Nil(t, dtlsAlert)
			if len(test.serverCIDs) == 0 {
				assertConnectionIDs(t, state, nil, nil, false)
			} else {
				assertConnectionIDs(t, state, test.clientCID, test.serverCIDs[0], true)
			}
		})
	}
}

func TestFlight13_1ParseRejectsHelloRetryRequestExtension(t *testing.T) {
	for name, test := range map[string]struct {
		extension   extension.Value
		expectedErr error
		description alert.Description
		isClient    bool
		generate    bool
	}{
		"ConnectionID": {
			extension: &extension.ConnectionID{}, expectedErr: dtlserrors.ErrExtensionNotAllowed,
			description: alert.IllegalParameter, isClient: true,
		},
		"Unsolicited": {
			extension: extension.Raw{Type: 0xfafa}, expectedErr: dtlserrors.ErrUnsolicitedExtension,
			description: alert.UnsupportedExtension, generate: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, state := testHandshakeConfig13(t), newTestState13(t, test.isClient)
			if test.generate {
				_, dtlsAlert, err := flight13GenerateForTest(
					t, dtlsflight13.Flight1, &handshakeTestContext13{state: state, cfg: cfg},
				)
				require.NoError(t, err)
				require.Nil(t, dtlsAlert)
			}
			rawServerHello := marshalHelloRetryRequestServerHello(t, cfg, []extension.Value{
				&extension13.SelectedVersion{Version: protocol.Version1_3}, test.extension,
			})
			cache := dtlsflight.NewCache()
			cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)

			nextFlight, dtlsAlert, err := flight13ParseForTest(
				t, dtlsflight13.Flight1, context.Background(), &handshakeTestContext13{
					state: state, cache: cache, cfg: cfg,
				},
			)
			require.ErrorIs(t, err, test.expectedErr)
			require.NotNil(t, dtlsAlert)
			assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: test.description}, dtlsAlert)
			assert.Zero(t, nextFlight)
		})
	}
}
