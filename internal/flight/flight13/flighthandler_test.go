// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"crypto/tls"
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/internal/extensionnegotiation"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProtectedFlightParseFailureClientCertificateRequired(t *testing.T) {
	failure := protectedFlightParseFailure(dtlserrors.ErrClientCertificateRequired)
	require.NotNil(t, failure)
	require.NotNil(t, failure.alert)
	assert.Equal(t, alert.Fatal, failure.alert.Level)
	assert.Equal(t, alert.CertificateRequired, failure.alert.Description)
	assert.ErrorIs(t, failure.err, dtlserrors.ErrClientCertificateRequired)
	var classified *alert.Alert
	require.ErrorAs(t, failure.err, &classified)
	assert.Equal(t, failure.alert, classified)
}

func TestPullProtectedHandshakeFlightReturnsDecodedItems(t *testing.T) {
	cache := dtlsflight.NewCache()
	rawEncryptedExtensions := marshalProtectedTestHandshake(t, 0, &handshake.MessageEncryptedExtensions{})
	rawFinished := marshalProtectedTestHandshake(t, 1, &handshake.MessageFinished{VerifyData: []byte{0x01}})
	cache.Push(rawEncryptedExtensions, EpochHandshake, 0, handshake.TypeEncryptedExtensions, false)
	cache.Push(rawFinished, EpochHandshake, 1, handshake.TypeFinished, false)

	pull := pullProtectedHandshakeFlight(cache, []dtlsflight.HandshakeCachePullRule{
		{Typ: handshake.TypeEncryptedExtensions, Epoch: EpochHandshake, IsClient: false},
		{Typ: handshake.TypeFinished, Epoch: EpochHandshake, IsClient: false},
	}, 0)

	require.True(t, pull.ready)
	require.Nil(t, pull.failure)
	assert.Equal(t, 2, pull.nextHandshakeSequence)
	require.Len(t, pull.items, 2)
	assert.Equal(t, rawEncryptedExtensions, pull.items[0].Raw.Data)
	assert.Equal(t, rawFinished, pull.items[1].Raw.Data)
	require.IsType(t, &handshake.MessageEncryptedExtensions{}, pull.items[0].Parsed.Message)
	require.IsType(t, &handshake.MessageFinished{}, pull.items[1].Parsed.Message)

	secondPull := pullProtectedHandshakeFlight(cache, []dtlsflight.HandshakeCachePullRule{
		{Typ: handshake.TypeEncryptedExtensions, Epoch: EpochHandshake, IsClient: false},
		{Typ: handshake.TypeFinished, Epoch: EpochHandshake, IsClient: false},
	}, 0)
	require.True(t, secondPull.ready)
	require.Nil(t, secondPull.failure)
	assert.Same(t, pull.items[0].Parsed, secondPull.items[0].Parsed)
	assert.Same(t, pull.items[1].Parsed, secondPull.items[1].Parsed)
}

func TestPullProtectedHandshakeFlightDistinguishesIncompleteAndInvalid(t *testing.T) {
	rule := []dtlsflight.HandshakeCachePullRule{
		{Typ: handshake.TypeEncryptedExtensions, Epoch: EpochHandshake, IsClient: false},
	}

	t.Run("missing", func(t *testing.T) {
		pull := pullProtectedHandshakeFlight(dtlsflight.NewCache(), rule, 0)
		assert.False(t, pull.ready)
		assert.Nil(t, pull.failure)
	})

	t.Run("sequence gap", func(t *testing.T) {
		cache := dtlsflight.NewCache()
		raw := marshalProtectedTestHandshake(t, 1, &handshake.MessageEncryptedExtensions{})
		cache.Push(raw, EpochHandshake, 1, handshake.TypeEncryptedExtensions, false)

		pull := pullProtectedHandshakeFlight(cache, rule, 0)
		assert.False(t, pull.ready)
		assert.Nil(t, pull.failure)
	})

	t.Run("sequence overflow", func(t *testing.T) {
		pull := pullProtectedHandshakeFlight(dtlsflight.NewCache(), rule, -1)
		require.True(t, pull.ready)
		require.NotNil(t, pull.failure)
		assert.ErrorIs(t, pull.failure.err, dtlserrors.ErrHandshakeSequenceOverflow)
		var classified *alert.Alert
		require.ErrorAs(t, pull.failure.err, &classified)
		assert.Equal(t, alert.DecodeError, classified.Description)
	})

	t.Run("malformed payload", func(t *testing.T) {
		header := handshake.Header{
			Type: handshake.TypeEncryptedExtensions, Length: 1, MessageSequence: 0, FragmentLength: 1,
		}
		raw, err := header.Marshal()
		require.NoError(t, err)
		raw = append(raw, 0x00)
		cache := dtlsflight.NewCache()
		cache.Push(raw, EpochHandshake, 0, handshake.TypeEncryptedExtensions, false)

		pull := pullProtectedHandshakeFlight(cache, rule, 0)
		require.True(t, pull.ready)
		require.NotNil(t, pull.failure)
		var classified *alert.Alert
		require.ErrorAs(t, pull.failure.err, &classified)
		assert.Equal(t, alert.DecodeError, classified.Description)
	})

	t.Run("known illegal placement", func(t *testing.T) {
		cache := dtlsflight.NewCache()
		raw := marshalProtectedTestHandshake(t, 0, &handshake.MessageEncryptedExtensions{
			Extensions: []extension.Value{extension.Raw{Type: extension.TypeExtendedMasterSecret}},
		})
		cache.Push(raw, EpochHandshake, 0, handshake.TypeEncryptedExtensions, false)

		pull := pullProtectedHandshakeFlight(cache, rule, 0)
		require.True(t, pull.ready)
		require.NotNil(t, pull.failure)
		assert.ErrorIs(t, pull.failure.err, dtlserrors.ErrExtensionNotAllowed)
		var classified *alert.Alert
		require.ErrorAs(t, pull.failure.err, &classified)
		assert.Equal(t, alert.IllegalParameter, classified.Description)
	})
}

func marshalProtectedTestHandshake(t *testing.T, sequence uint16, message handshake.Message) []byte {
	t.Helper()

	raw, err := (&handshake.Handshake{
		Header:  handshake.Header{MessageSequence: sequence},
		Message: message,
	}).Marshal()
	require.NoError(t, err)

	return raw
}

func TestHandleFlight3ProtectedHandshakeRetainsCertificateRequest(t *testing.T) {
	request := &handshake.MessageCertificateRequest13{
		Extensions: []extension.Value{
			&extension.SignatureAlgorithms{Schemes: []uint16{0x0403}},
		},
	}
	items := []dtlsflight.DecodedHandshakeCacheItem{{
		Raw: &dtlsflight.HandshakeCacheItem{Typ: handshake.TypeCertificateRequest},
		Parsed: &handshake.Handshake{
			Message: request,
		},
	}}
	flightCtx := &handshakeContext{
		state: &dtlsstate.State13{Common: &dtlsstate.Common{}},
		protectedHandshakeHandler: func(_ dtlsconfig.CipherSuite, got []dtlsflight.DecodedHandshakeCacheItem) error {
			assert.Same(t, request, got[0].Parsed.Message)

			return nil
		},
	}

	failure := handleFlight3ProtectedHandshake(flightCtx, items)
	require.Nil(t, failure)
	assert.Same(t, request, flightCtx.state.RemoteCertificateRequest)
}

func TestFlight3ParseClearsConnectionIDAfterInvalidEncryptedExtensions(t *testing.T) {
	state := dtlsstate.NewState13(true)
	state.CommitNegotiatedExtensions(&extensionnegotiation.ConnectionID{ClientCID: []byte{1}, ServerCID: []byte{2}})
	state.SetRemoteEpoch(EpochHandshake)

	cache := dtlsflight.NewCache()
	cache.Push(marshalProtectedTestHandshake(t, 0, &handshake.MessageEncryptedExtensions{
		Extensions: []extension.Value{extension.Raw{Type: 0xfafa}},
	}), EpochHandshake, 0, handshake.TypeEncryptedExtensions, false)
	cache.Push(marshalProtectedTestHandshake(t, 1, &handshake.MessageFinished{}), EpochHandshake, 1, handshake.TypeFinished, false) //nolint:lll
	handlerCalled := false
	next, dtlsAlert, err := flight3Parse(t.Context(), nil, &handshakeContext{
		state: &state,
		cache: cache,
		protectedHandshakeHandler: func(
			_ dtlsconfig.CipherSuite,
			_ []dtlsflight.DecodedHandshakeCacheItem,
		) error {
			handlerCalled = true

			return nil
		},
	})

	require.ErrorIs(t, err, dtlserrors.ErrUnsolicitedExtension)
	assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.UnsupportedExtension}, dtlsAlert)
	assert.Zero(t, next)
	assert.False(t, handlerCalled)
	assert.Nil(t, state.LocalConnectionIDForInboundRecords())
	assert.Nil(t, state.LocalConnectionID())
	assert.Nil(t, state.RemoteConnectionID)
	assert.Equal(t, dtlsstate.CIDState{}, state.CID)
}

func TestFlight5ClientCertificateClonesCertificateAuthorities(t *testing.T) {
	authority := []byte{0x01, 0x02}
	request := &handshake.MessageCertificateRequest13{Extensions: []extension.Value{
		&extension.SignatureAlgorithms{Schemes: []uint16{0x0403}},
		&extension13.CertificateAuthorities{Authorities: [][]byte{authority}},
	}}
	cfg := &dtlsconfig.HandshakeConfig{
		LocalGetClientCertificate: func(info *dtlsconfig.CertificateRequestInfo) (*tls.Certificate, error) {
			info.AcceptableCAs[0][0] = 0xff

			return &tls.Certificate{}, nil
		},
	}

	_, err := flight5ClientCertificate(cfg, request)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x02}, authority)
	assert.Equal(t, []byte{0x01, 0x02}, request.Extensions[1].(*extension13.CertificateAuthorities).Authorities[0]) //nolint:forcetypeassert,lll
}

func TestFlight4GenerateCertificateAuthenticatedFlight(t *testing.T) {
	flightCtx, certificate := flight4TestContext(t)
	certificate.Certificate = append(certificate.Certificate, []byte{0x01, 0x02, 0x03})
	flightCtx.cfg.LocalCertificates = []tls.Certificate{certificate}

	pkts, dtlsAlert, err := flight4Generate(nil, flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, pkts, 5)

	expectedTypes := []handshake.Type{
		handshake.TypeServerHello,
		handshake.TypeEncryptedExtensions,
		handshake.TypeCertificate,
		handshake.TypeCertificateVerify,
		handshake.TypeFinished,
	}
	for i, pkt := range pkts {
		hs, ok := pkt.Record.Content.(*handshake.Handshake)
		require.True(t, ok)
		assert.Equal(t, expectedTypes[i], hs.Message.Type())
		assert.Equal(t, i > 0, pkt.ShouldEncrypt)
		assert.Equal(t, i == 1, pkt.ResetLocalSequenceNumber)
		if i > 0 {
			assert.Equal(t, EpochHandshake, pkt.Record.Header.Epoch)
		}
	}

	certificateHandshake := pkts[2].Record.Content.(*handshake.Handshake)                //nolint:forcetypeassert
	certificateMessage := certificateHandshake.Message.(*handshake.MessageCertificate13) //nolint:forcetypeassert
	assert.Empty(t, certificateMessage.CertificateRequestContext)
	require.Len(t, certificateMessage.CertificateList, len(certificate.Certificate))
	for i, entry := range certificateMessage.CertificateList {
		assert.Equal(t, certificate.Certificate[i], entry.CertificateData)
	}

	certificateVerifyHandshake := pkts[3].Record.Content.(*handshake.Handshake)                   //nolint:forcetypeassert
	certificateVerify := certificateVerifyHandshake.Message.(*handshake.MessageCertificateVerify) //nolint:forcetypeassert
	assert.Empty(t, certificateVerify.Signature)
	assert.Same(t, certificate.PrivateKey, pkts[3].CertificateVerifySigner)
}

func TestFlight4GenerateReusesNegotiatedConnectionID(t *testing.T) {
	flightCtx, _ := flight4TestContext(t)
	_, offer, err := extensionnegotiation.FinalizeClientHello(&handshake.MessageClientHello{
		Extensions: []extension.Value{
			&extension.ConnectionID{CID: []byte{0x01}},
		},
	}, nil)
	require.NoError(t, err)
	flightCtx.state.RemoteClientHelloSnapshots.Reset()
	require.NoError(t, flightCtx.state.RemoteClientHelloSnapshots.Record(offer))

	generatorCalls := 0
	flightCtx.cfg.ConnectionIDGenerator = func() []byte {
		generatorCalls++

		return []byte{0x01}
	}

	for range 2 {
		packets, dtlsAlert, err := flight4Generate(nil, flightCtx)
		require.NoError(t, err)
		require.Nil(t, dtlsAlert)
		require.NotEmpty(t, packets)
		serverHelloHandshake, ok := packets[0].Record.Content.(*handshake.Handshake)
		require.True(t, ok)
		serverHello, ok := serverHelloHandshake.Message.(*handshake.MessageServerHello)
		require.True(t, ok)
		connectionID, ok := serverHello.Extensions[len(serverHello.Extensions)-1].(*extension.ConnectionID)
		require.True(t, ok)
		assert.Equal(t, []byte{0x01}, connectionID.CID)
	}

	assert.Equal(t, 1, generatorCalls)
}

func TestFlight4GenerateCertificateFailures(t *testing.T) {
	tests := map[string]struct {
		configure     func(*handshakeContext)
		expectedError error
		expectedAlert alert.Description
	}{
		"missing certificate": {
			configure: func(ctx *handshakeContext) {
				ctx.cfg.LocalCertificates = nil
			},
			expectedError: dtlserrors.ErrNoCertificates,
			expectedAlert: alert.HandshakeFailure,
		},
		"invalid private key": {
			configure: func(ctx *handshakeContext) {
				ctx.cfg.LocalCertificates[0].PrivateKey = struct{}{}
			},
			expectedError: dtlserrors.ErrInvalidPrivateKey,
			expectedAlert: alert.HandshakeFailure,
		},
		"no common signature scheme": {
			configure: func(ctx *handshakeContext) {
				ctx.state.RemoteSignatureSchemes = nil
			},
			expectedError: dtlserrors.ErrNoAvailableSignatureSchemes,
			expectedAlert: alert.InsufficientSecurity,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			flightCtx, _ := flight4TestContext(t)
			test.configure(flightCtx)

			pkts, dtlsAlert, err := flight4Generate(nil, flightCtx)
			require.ErrorIs(t, err, test.expectedError)
			assert.Nil(t, pkts)
			require.NotNil(t, dtlsAlert)
			assert.Equal(t, alert.Fatal, dtlsAlert.Level)
			assert.Equal(t, test.expectedAlert, dtlsAlert.Description)
		})
	}
}

func flight4TestContext(t *testing.T) (*handshakeContext, tls.Certificate) {
	t.Helper()

	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	keypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)
	signatureSchemes := signaturehash.Algorithms13()
	_, offer, err := extensionnegotiation.FinalizeClientHello(&handshake.MessageClientHello{
		Extensions: []extension.Value{
			&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
			&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(signaturehash.Algorithms13())},
			&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}},
			&extension13.ClientKeyShare{},
		},
	}, nil)
	require.NoError(t, err)
	var remoteOffers extensionnegotiation.ClientHelloSnapshots
	require.NoError(t, remoteOffers.Record(offer))

	return &handshakeContext{
		state: &dtlsstate.State13{
			Common: &dtlsstate.Common{
				CipherSuite:                ciphersuite.NewTLSAes128GcmSha256(),
				RemoteClientHelloSnapshots: remoteOffers,
			},
			LocalKeypair:           keypair,
			RemoteSignatureSchemes: append([]signaturehash.Algorithm(nil), signatureSchemes...),
		},
		cfg: &dtlsconfig.HandshakeConfig{
			LocalCertificates:     []tls.Certificate{certificate},
			LocalSignatureSchemes: append([]signaturehash.Algorithm(nil), signatureSchemes...),
		},
	}, certificate
}
