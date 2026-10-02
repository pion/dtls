// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"crypto"
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/stretchr/testify/require"
)

func TestSelectPSK(t *testing.T) {
	for _, test := range []struct {
		name                         string
		certificate, known, wrongKey bool
		wantError                    error
		wantAlert                    alert.Description
	}{
		{name: "unknown identity without certificate", wantError: dtlserrors.ErrPSKNotNegotiated, wantAlert: alert.HandshakeFailure},
		{name: "unknown identity with certificate", certificate: true},
		{name: "skip unknown identity", known: true},
		{name: "bad binder cannot fall back", certificate: true, known: true, wrongKey: true, wantError: dtlserrors.ErrVerifyDataMismatch, wantAlert: alert.DecryptError},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testHandshakeConfig13(t)
			if !test.certificate {
				cfg.LocalCertificates = nil
			}
			var identities []string
			cfg.LocalPSKCallback = func(identity []byte) ([]byte, error) {
				identities = append(identities, string(identity))
				if !test.known || string(identity) != "known" {
					return nil, nil
				}
				if test.wrongKey {
					return []byte("wrong"), nil
				}

				return []byte("secret"), nil
			}
			base := &handshake.MessageClientHello{
				Version: protocol.Version1_2, CipherSuiteIDs: []uint16{0x1301},
				CompressionMethods: []*protocol.CompressionMethod{{ID: 0}},
			}
			hello, _, err := FinalizeClientHelloWithPSKs(base, cfg, []PSK{
				{Identity: []byte("unknown"), Secret: []byte("other"), Hash: crypto.SHA256, External: true},
				{Identity: []byte("known"), Secret: []byte("secret"), Hash: crypto.SHA256, External: true},
			}, NewTranscript())
			require.NoError(t, err)
			raw := rawHandshakeMessage13(t, 0, hello)
			state := newTestState13(t, false)
			state.CipherSuite = cfg.LocalCipherSuites[0]
			transcript := NewTranscript()
			c := &handshakeContext{state: state, cfg: cfg, transcript: transcript}
			err = c.selectPSK(hello, raw)
			require.Equal(t, []string{"unknown", "known"}, identities)
			if test.wantError != nil {
				require.ErrorIs(t, err, test.wantError)
				var gotAlert *alert.Alert
				require.ErrorAs(t, err, &gotAlert)
				require.Equal(t, test.wantAlert, gotAlert.Description)
				require.Empty(t, state.PSK)

				return
			}
			require.NoError(t, err)
			if test.known {
				require.Equal(t, []byte("secret"), state.PSK)
				require.Equal(t, uint16(1), state.PSKIdentity)
				require.Equal(t, []byte("known"), state.IdentityHint)
			} else {
				require.Empty(t, state.PSK)
			}
		})
	}
}
