// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/sha256"
	"hash"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlshandshake "github.com/pion/dtls/v3/internal/handshake"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/internal/util"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
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

var testCurves13 = []elliptic.Curve{elliptic.X25519, elliptic.P256, elliptic.P384} //nolint:gochecknoglobals

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
	state      *dtlsstate.State
	cache      *dtlsflight.Cache
	cfg        *dtlsconfig.HandshakeConfig
	transcript *dtlshandshake.Transcript
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
			return dtlshandshake.AppendInboundHandshakeCacheItems(flightCtx.transcript, cipherSuite, items)
		},
		func(state *dtlsstate.State) error {
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
	preMasterSecret, transcriptHash []byte,
) (dtlsstate.HandshakeTrafficSecrets13, error) {
	hashSize := hashFunc().Size()
	zeroSecret := make([]byte, hashSize)
	earlySecret, err := keyschedule.HkdfExtract(hashFunc, nil, zeroSecret)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets13{}, err
	}

	derivedSecret, err := keyschedule.DeriveSecret(hashFunc, earlySecret, "derived", nil)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets13{}, err
	}

	handshakeSecret, err := keyschedule.HkdfExtract(hashFunc, derivedSecret, preMasterSecret)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets13{}, err
	}

	clientSecret, err := keyschedule.HkdfExpandLabel(hashFunc, handshakeSecret, "c hs traffic", transcriptHash, hashSize)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets13{}, err
	}
	serverSecret, err := keyschedule.HkdfExpandLabel(hashFunc, handshakeSecret, "s hs traffic", transcriptHash, hashSize)
	if err != nil {
		return dtlsstate.HandshakeTrafficSecrets13{}, err
	}

	return dtlsstate.HandshakeTrafficSecrets13{Client: clientSecret, Server: serverSecret}, nil
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

	state := &dtlsstate.State{}

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
	state := &dtlsstate.State{}

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
	state := &dtlsstate.State{}

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
	state := &dtlsstate.State{}

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

	state := &dtlsstate.State{}
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

	state := &dtlsstate.State{}
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

	state := &dtlsstate.State{}
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

	state := &dtlsstate.State{}
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
	state := &dtlsstate.State{}
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
	state := &dtlsstate.State{
		Cookie:         []byte{0x01, 0x02, 0x03, 0x04},
		RemoteVersions: []protocol.Version{protocol.Version1_3},
	}
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
	state := &dtlsstate.State{
		RemoteVersions: []protocol.Version{protocol.Version1_3},
		LocalKeyEntries: []extension.KeyShareEntry{
			{Group: originalKeypair.Curve, KeyExchange: originalKeypair.PublicKey},
		},
		RemoteKeyEntries: &[]extension.KeyShareEntry{{Group: selectedGroup}},
	}
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
	state := &dtlsstate.State{
		RemoteVersions: []protocol.Version{protocol.Version1_3},
		LocalKeyEntries: []extension.KeyShareEntry{
			{Group: keypair.Curve, KeyExchange: keypair.PublicKey},
		},
		RemoteKeyEntries: &[]extension.KeyShareEntry{{Group: selectedGroup}},
	}
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
	state := &dtlsstate.State{}
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
	cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)
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
	assert.Equal(t, group, state.NamedCurve)
	assert.Equal(t, random.RandomBytes, state.RemoteRandom.RandomBytes)
	require.NotNil(t, state.RemoteKeyEntries)
	require.Len(t, *state.RemoteKeyEntries, 1)
	assert.Equal(t, group, (*state.RemoteKeyEntries)[0].Group)

	clientKeypair := state.LocalKeypairs[group]
	require.NotNil(t, clientKeypair)
	expected, err := prf.PreMasterSecret(clientKeypair.PublicKey, serverKeypair.PrivateKey, group)
	require.NoError(t, err)
	assert.Equal(t, expected, state.PreMasterSecret)
	assert.NotEmpty(t, state.PreMasterSecret)
	transcriptHash := hashTranscript13(clientHelloCanonical, serverHelloCanonical)
	expectedSecrets, err := deriveHandshakeTrafficSecrets13(
		state.CipherSuite.HashFunc(), expected, transcriptHash,
	)
	require.NoError(t, err)
	assert.Equal(t, expectedSecrets, state.HandshakeTrafficSecrets13)
	assert.NotEqual(t, state.HandshakeTrafficSecrets13.Client, state.HandshakeTrafficSecrets13.Server)
	assert.True(t, state.CipherSuite.IsInitialized())
}

func TestFlight13_3ParseDrainsQueuedProtectedHandshakeBeforeEncryptedExtensions(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{IsClient: true}
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
	rawEncryptedExtensions, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageEncryptedExtensions{},
	}).Marshal()
	require.NoError(t, err)

	cache := dtlsflight.NewCache()
	cache.Push(rawServerHello, cfg.InitialEpoch, 0, handshake.TypeServerHello, false)
	drained := false
	conn := &flight13QueuedPacketConn{
		handleQueuedPackets: func(context.Context) error {
			drained = true
			assert.True(t, state.CipherSuite.IsInitialized())
			assert.Equal(t, dtlsflight13.EpochHandshake, state.GetRemoteEpoch())
			cache.Push(rawEncryptedExtensions, dtlsflight13.EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)

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
	assert.Equal(t, 2, state.HandshakeRecvSequence)
}

func TestFlight13ClientParsesEncryptedExtensionsFromProtectedRecord(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cache := dtlsflight.NewCache()
	conn := &Conn{
		fragmentBuffer:          newFragmentBuffer(),
		handshakeCache:          cache,
		maximumTransmissionUnit: defaultMTU,
		replayProtectionWindow:  defaultReplayProtectionWindow,
		log:                     logging.NewDefaultLoggerFactory().NewLogger("dtls"),
		state:                   dtlsstate.State{IsClient: true},
	}
	state := &conn.state
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
	preMasterSecret, err := prf.PreMasterSecret(clientKeypair.PublicKey, serverKeypair.PrivateKey, group)
	require.NoError(t, err)
	secrets, err := deriveHandshakeTrafficSecrets13(
		cfg.LocalCipherSuites[0].HashFunc(),
		preMasterSecret,
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
	protectedRecord := sealTestProtectedHandshakeRecord(t, peerCipherSuite, rawEncryptedExtensions)
	protectedRaw, err := protectedRecord.Marshal()
	require.NoError(t, err)
	conn.encryptedPackets = []addrPkt{{data: protectedRaw}}

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
	assert.Equal(t, 2, state.HandshakeRecvSequence)

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
	state := &dtlsstate.State{}
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
	nextFlight, dtlsAlert, err := flight13ParseForTest(t, Flight1, context.Background(), &handshakeTestContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})

	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight5, nextFlight)
	expectedTranscript := append(append(append([]byte(nil), clientHelloCanonical...), serverHelloCanonical...),
		encryptedExtensionsCanonical...)
	assert.Equal(t, expectedTranscript, transcript.Bytes())
}

func TestFlight13ClientParseAppendsHRRTranscriptOrder(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}
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

	nextFlight, dtlsAlert, err = flight13ParseForTest(t, Flight3, context.Background(), &handshakeTestContext13{
		state:      state,
		cache:      cache,
		cfg:        cfg,
		transcript: transcript,
	})
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight5, nextFlight)

	clientHello1Hash := hashTranscript13(clientHello1Canonical)
	messageHash := canonicalTranscriptHandshake13(handshake.TypeMessageHash, clientHello1Hash)
	expectedTranscript := append(append(append(append(append([]byte(nil), messageHash...), helloRetryRequestCanonical...),
		clientHello2Canonical...), serverHelloCanonical...), encryptedExtensionsCanonical...)
	assert.Equal(t, expectedTranscript, transcript.Bytes())
}

func TestFlight13_3ParseKeepsReadingWithoutServerHello(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	state := &dtlsstate.State{}

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
	state := &dtlsstate.State{}
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
	state := &dtlsstate.State{}
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
	state := &dtlsstate.State{}
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
	state := &dtlsstate.State{}
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
	state := &dtlsstate.State{}

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

	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		NamedCurve:   elliptic.X25519,
		LocalKeypair: staleServerKeypair,
	}
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
	assert.Equal(t, elliptic.P384, state.NamedCurve)
	assert.Same(t, staleServerKeypair, state.LocalKeypair)
	assert.Empty(t, state.PreMasterSecret)
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

	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
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
	assert.Equal(t, elliptic.X25519MLKEM768, state.NamedCurve)
	assert.Nil(t, state.LocalKeypair)
	assert.Empty(t, state.PreMasterSecret)
}

func TestFlight13_0ParseSelectsServerPreferredGroupFromClientShares(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768, elliptic.X25519}

	mlkemKeypair, err := elliptic.GenerateKeypair(elliptic.X25519MLKEM768)
	require.NoError(t, err)
	x25519Keypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)

	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
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
	assert.Equal(t, elliptic.X25519MLKEM768, state.NamedCurve)
	assert.Nil(t, state.LocalKeypair)
	assert.Empty(t, state.PreMasterSecret)
}

func TestFlight13_0ParseRequestsPreferredGroupWhenShareMissing(t *testing.T) {
	cfg := testHandshakeConfig13(t)
	cfg.EllipticCurves = []elliptic.Curve{elliptic.X25519MLKEM768, elliptic.X25519}

	x25519Keypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)

	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
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
	assert.Equal(t, elliptic.X25519MLKEM768, state.NamedCurve)

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

	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
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
	state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
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
	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		Cookie:       cookie,
	}
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
	t *testing.T, state *dtlsstate.State, cfg *dtlsconfig.HandshakeConfig,
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		assert.Equal(t, protocol.Version1_2, serverHello.Version)
		assert.Equal(t, [32]byte(handshake.HelloRetryRequestRandom()), serverHello.Random.MarshalFixed())
	})

	t.Run("ResetsHandshakeSendSequence", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{
			LocalVersion:          protocol.Version1_3,
			CipherSuite:           cfg.LocalCipherSuites[0],
			HandshakeSendSequence: 7,
		}

		_, dtlsAlert, err := flight13GenerateForTest(
			t, Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)

		assert.Equal(t, 0, state.HandshakeSendSequence)
	})

	t.Run("RejectsWithoutCipherSuite", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, Flight2, flight13_2Context(state, dtlsflight.NewCache(), cfg),
		)
		require.ErrorIs(t, err, dtlserrors.ErrCipherSuiteUnset)
		require.Nil(t, dtlsAlert)
		require.Nil(t, pkts)
	})

	t.Run("AlwaysIncludesSupportedVersions", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		supportedVersions, ok := findSupportedVersions(serverHello.Extensions)
		require.True(t, ok, "SupportedVersions extension must always be present")
		assert.Equal(t, []protocol.Version{protocol.Version1_3}, supportedVersions.Versions)
		assert.True(t, supportedVersions.IsSelectedVersion())
	})

	t.Run("IncludesCipherSuiteAndCompressionMethod", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		_, hasKeyShare := findKeyShare(serverHello.Extensions)
		assert.False(t, hasKeyShare, "KeyShare must be omitted when no remote key entries were offered")

		_, hasCookie := findCookie(serverHello.Extensions)
		assert.False(t, hasCookie, "Cookie must be omitted when no cookie is set")

		require.Len(t, serverHello.Extensions, 1)
	})

	t.Run("IncludesKeyShareWhenRemoteKeyEntriesPresent", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, NamedCurve: elliptic.X25519}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		keyShare, ok := findKeyShare(serverHello.Extensions)
		require.True(t, ok, "KeyShare must be present when remote key entries were offered")
		require.NotNil(t, keyShare.SelectedGroup)
		assert.Equal(t, elliptic.X25519, *keyShare.SelectedGroup)
	})

	t.Run("IncludesCookieWhenSet", func(t *testing.T) {
		cookie := []byte{0x01, 0x02, 0x03, 0x04}
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
		cfg := testHandshakeConfig13(t)

		serverHello := serverHelloFromFlight13_2(t, state, cfg)

		cookieExt, ok := findCookie(serverHello.Extensions)
		require.True(t, ok, "Cookie must be present when set on state")
		assert.Equal(t, cookie, cookieExt.Cookie)
	})

	t.Run("IncludesAllExtensionsTogether", func(t *testing.T) {
		cookie := []byte{0xaa, 0xbb}
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, NamedCurve: elliptic.P256, Cookie: cookie}
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

		state := &dtlsstate.State{
			LocalVersion: protocol.Version1_3,
			CipherSuite:  cfg.LocalCipherSuites[0],
			LocalKeypair: keypair,
			LocalRandom:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01, 0x02, 0x03}},
		}

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, Flight4, &handshakeTestContext13{state: state, cfg: cfg},
		)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		require.Len(t, pkts, 2)
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
	})

	t.Run("RejectsWithoutCipherSuite", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3}

		pkts, dtlsAlert, err := flight13GenerateForTest(
			t, Flight4, &handshakeTestContext13{state: state, cfg: cfg},
		)
		require.ErrorIs(t, err, dtlserrors.ErrCipherSuiteUnset)
		require.Nil(t, dtlsAlert)
		require.Nil(t, pkts)
	})

	t.Run("RejectsWithoutLocalKeypair", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		state := &dtlsstate.State{
			LocalVersion: protocol.Version1_3,
			CipherSuite:  cfg.LocalCipherSuites[0],
		}

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

	state := &dtlsstate.State{
		LocalVersion: protocol.Version1_3,
		CipherSuite:  cfg.LocalCipherSuites[0],
		LocalKeypair: keypair,
		LocalRandom:  handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
	}

	pkts, dtlsAlert, err := flight13GenerateForTest(
		t, Flight4, &handshakeTestContext13{state: state, cfg: cfg},
	)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 2)

	assert.Equal(t, uint16(0), pkts[0].Record.Header.Epoch)
	assert.False(t, pkts[0].ShouldEncrypt)
	assert.Equal(t, dtlsflight13.EpochHandshake, pkts[1].Record.Header.Epoch)
	assert.True(t, pkts[1].ShouldEncrypt)
	assert.True(t, pkts[1].ResetLocalSequenceNumber)
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
	state *dtlsstate.State, cache *dtlsflight.Cache, cfg *dtlsconfig.HandshakeConfig,
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
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

		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
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
		assert.Equal(t, elliptic.X25519MLKEM768, state.NamedCurve)
		assert.Equal(t, elliptic.X25519MLKEM768, state.LocalKeypair.Curve)
		assert.Len(t, state.LocalKeypair.PublicKey, elliptic.X25519MLKEM768ServerPublicKeySize)

		clientSecret, err := prf.PreMasterSecret(
			state.LocalKeypair.PublicKey,
			clientKeypair.PrivateKey,
			elliptic.X25519MLKEM768,
		)
		require.NoError(t, err)
		assert.Equal(t, clientSecret, state.PreMasterSecret)
		assert.Len(t, state.PreMasterSecret, elliptic.X25519MLKEM768SharedSecretSize)
	})

	t.Run("RejectsUnsupportedSupportedGroupsAfterMatchingCookie", func(t *testing.T) {
		cfg := testHandshakeConfig13(t)
		cfg.EllipticCurves = []elliptic.Curve{elliptic.P256}
		clientKeypair, err := elliptic.GenerateKeypair(elliptic.P384)
		require.NoError(t, err)

		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
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
		assert.Empty(t, state.PreMasterSecret)
		assert.Nil(t, state.LocalKeypair)
		assert.Zero(t, state.NamedCurve)
	})

	t.Run("KeepsWaitingWhenNoClientHelloCached", func(t *testing.T) {
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie, ServerName: "original.example"}
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie, ServerName: "original.example"}
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
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
		state := &dtlsstate.State{LocalVersion: protocol.Version1_3, Cookie: cookie}
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
