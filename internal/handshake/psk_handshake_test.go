// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/pion/dtls/v4/internal/ech"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v4/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
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
		{name: "select second identity", known: true},
		{name: "bad binder cannot fall back", certificate: true, known: true, wrongKey: true, wantError: dtlserrors.ErrVerifyDataMismatch, wantAlert: alert.DecryptError},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testHandshakeConfig13(t)
			if !test.certificate {
				cfg.LocalCertificates = nil
			}
			var identities [][]byte
			calls := 0
			cfg.SelectPSK = func(offered [][]byte) (int, []byte, crypto.Hash, error) {
				calls++
				identities = offered
				if !test.known {
					return -1, nil, 0, nil
				}
				if test.wrongKey {
					return 1, []byte("wrong"), crypto.SHA256, nil
				}

				return 1, []byte("secret"), crypto.SHA256, nil
			}
			base := &handshake.MessageClientHello{
				Version: protocol.Version1_2, CipherSuiteIDs: []uint16{0x1301},
				CompressionMethods: []*protocol.CompressionMethod{{ID: 0}},
			}
			hello, _, err := FinalizeClientHelloWithPSKs(base, cfg, []dtlsstate.PSK{
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
			require.Equal(t, [][]byte{[]byte("unknown"), []byte("known")}, identities)
			require.Equal(t, 1, calls)
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

func TestFinalizeECHClientHello(t *testing.T) {
	if !ech.Available() {
		t.Skip("HPKE requires Go 1.26")
	}
	list, err := hex.DecodeString("0045fe0d0041590020002092a01233db2218518ccbbbbc24df20686af417b37388de6460e94011974777090004000100010012636c6f7564666c6172652d6563682e636f6d0000")
	require.NoError(t, err)
	hooks := 0
	cfg := testHandshakeConfig13(t)
	cfg.ECHConfigList = list
	cfg.ServerName = "secret.example"
	cfg.ClientHelloMessageHook = func(hello handshake.MessageClientHello) handshake.Message {
		hooks++

		return &hello
	}
	state, packets, transcript := newFlight13ClientHelloFixture(t, cfg)
	message, ok := packets[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	outer, ok := message.Message.(*handshake.MessageClientHello)
	require.True(t, ok)
	require.Equal(t, 1, hooks)
	require.NotNil(t, state.ECH)
	body, err := outer.Marshal()
	require.NoError(t, err)
	require.Equal(t, state.ECH.Outer, body)
	require.NotEqual(t, state.ECH.Inner, body)
	setFlight13HandshakeSequence(t, packets[0], 7)
	fsm, err := newFSM13(state, dtlsflight.NewCache(), cfg, dtlsflight13.Flight1, packets, nil)
	require.NoError(t, err)
	require.NotNil(t, fsm.transcript.echInner)
	require.Equal(t, canonicalTranscriptHandshake13(handshake.TypeClientHello, body), fsm.transcript.Bytes())
	require.NoError(t, fsm.transcript.selectECHInner())
	require.Equal(t, canonicalTranscriptHandshake13(handshake.TypeClientHello, state.ECH.Inner), fsm.transcript.Bytes())
	require.Equal(t, uint16(7), fsm.transcript.order[0].ID.Seq)
	_, _, err = transcript.FinalizeClientHello(state, cfg, outer, nil)
	require.ErrorIs(t, err, ech.ErrUnsupported)
}
