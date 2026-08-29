// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlight5GenerateUsesRetainedServerKeyExchange(t *testing.T) {
	state := dtlsstate.NewState12(true)
	cipherSuite := ciphersuite.ForID(cryptosuite.TLS_PSK_WITH_AES_128_CCM)
	state.CipherSuite = cipherSuite
	state.MasterSecret = make([]byte, 48)
	require.NoError(t, state.InitCipherSuite())
	state.LocalVerifyData = []byte{0x01}
	serverKeyExchange := &handshake.MessageServerKeyExchange{IdentityHint: []byte("retained")}
	state.SetRemoteServerKeyExchange(serverKeyExchange)

	cache := dtlsflight.NewCache()
	cache.Push([]byte{byte(handshake.TypeServerKeyExchange)}, 0, 0, handshake.TypeServerKeyExchange, false)
	cfg := &dtlsconfig.HandshakeConfig{
		LocalPSKIdentityHint: []byte("client"),
		LocalPSKCallback: func([]byte) ([]byte, error) {
			require.FailNow(t, "retained ServerKeyExchange was processed twice")

			return nil, nil
		},
	}

	packets, dtlsAlert, err := flight5Generate(nil, &state, cache, cfg)
	require.NoError(t, err)
	assert.Nil(t, dtlsAlert)
	assert.NotEmpty(t, packets)
	assert.Same(t, serverKeyExchange, state.RemoteServerKeyExchange())
}

func TestHandleServerKeyExchangeClonesIdentityHint(t *testing.T) {
	state := dtlsstate.NewState12(true)
	state.CipherSuite = ciphersuite.ForID(cryptosuite.TLS_PSK_WITH_AES_128_CCM)
	message := &handshake.MessageServerKeyExchange{IdentityHint: []byte("server")}
	cfg := &dtlsconfig.HandshakeConfig{
		LocalPSKCallback: func(identityHint []byte) ([]byte, error) {
			identityHint[0] = 'X'

			return []byte("secret"), nil
		},
	}

	dtlsAlert, err := handleServerKeyExchange(nil, &state, cfg, message)
	require.NoError(t, err)
	assert.Nil(t, dtlsAlert)
	assert.Equal(t, []byte("server"), message.IdentityHint)
	assert.Equal(t, []byte("server"), state.IdentityHint)
}
