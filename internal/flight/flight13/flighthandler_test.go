// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"crypto/tls"
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
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
}

func TestFlight4GenerateCertificateAuthenticatedFlight(t *testing.T) {
	flightCtx, certificate := flight4TestContext13(t)
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
			flightCtx, _ := flight4TestContext13(t)
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

func flight4TestContext13(t *testing.T) (*handshakeContext, tls.Certificate) {
	t.Helper()

	certificate, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	keypair, err := elliptic.GenerateKeypair(elliptic.X25519)
	require.NoError(t, err)
	signatureSchemes := signaturehash.Algorithms13()

	return &handshakeContext{
		state: &dtlsstate.State13{
			Common: &dtlsstate.Common{
				CipherSuite: ciphersuite.NewTLSAes128GcmSha256(),
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
