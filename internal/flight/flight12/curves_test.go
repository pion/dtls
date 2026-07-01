// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/require"
)

func TestFlight12ClientHelloFiltersX25519MLKEM768(t *testing.T) {
	cfg := &dtlsconfig.HandshakeConfig{
		EllipticCurves: []elliptic.Curve{
			elliptic.X25519MLKEM768,
			elliptic.P256,
		},
		LocalCipherSuites: []dtlsconfig.CipherSuite{
			ciphersuite.ForID(ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, nil),
		},
	}
	state := &dtlsstate.State{}

	pkts, _, err := generateForTest(t, Flight1, nil, state, nil, cfg)
	require.NoError(t, err)
	require.Equal(t, elliptic.P256, state.NamedCurve)

	content, ok := pkts[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	clientHello, ok := content.Message.(*handshake.MessageClientHello)
	require.True(t, ok)

	var supportedGroups *extension.SupportedEllipticCurves
	for _, ext := range clientHello.Extensions {
		if groups, ok := ext.(*extension.SupportedEllipticCurves); ok {
			supportedGroups = groups
		}
	}
	require.NotNil(t, supportedGroups)
	require.Equal(t, []elliptic.Curve{elliptic.P256}, supportedGroups.EllipticCurves)
}

func TestFlight12ServerSelectsClassicalCurveFromClientGroups(t *testing.T) {
	cfg := &dtlsconfig.HandshakeConfig{
		EllipticCurves: []elliptic.Curve{
			elliptic.X25519MLKEM768,
			elliptic.P256,
		},
	}

	selected, ok := selectDTLS12EllipticCurve(cfg.EllipticCurves, []elliptic.Curve{
		elliptic.X25519MLKEM768,
		elliptic.P256,
	})
	require.True(t, ok)
	require.Equal(t, elliptic.P256, selected)

	_, ok = selectDTLS12EllipticCurve(cfg.EllipticCurves, []elliptic.Curve{
		elliptic.X25519MLKEM768,
	})
	require.False(t, ok)
}

func TestFlight12RejectsX25519MLKEM768ServerKeyExchange(t *testing.T) {
	state := &dtlsstate.State{
		CipherSuite: ciphersuite.ForID(ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, nil),
	}

	dtlsAlert, err := handleServerKeyExchange(
		nil,
		state,
		&dtlsconfig.HandshakeConfig{},
		&handshake.MessageServerKeyExchange{NamedCurve: elliptic.X25519MLKEM768},
	)
	require.ErrorIs(t, err, dtlserrors.ErrUnsupportedEllipticCurveVersion)
	require.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlsAlert)
}
