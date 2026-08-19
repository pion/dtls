// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	profile80  extension.SRTPProtectionProfile = extension.SRTP_AES128_CM_HMAC_SHA1_80
	profile32  extension.SRTPProtectionProfile = extension.SRTP_AES128_CM_HMAC_SHA1_32
	initialMKI                                 = "initial"
	finalMKI                                   = "final"
)

func TestFlight12ServerHelloUsesFinalSRTPOffer(t *testing.T) {
	for _, test := range []struct {
		name, serverMKI, hookMKI, wantMKI string
		flight                            Flight
		wantError                         bool
	}{
		{name: "echo", flight: Flight4, serverMKI: finalMKI, wantMKI: finalMKI},
		{name: "decline", flight: Flight4, serverMKI: "other"},
		{name: "hook cannot override decline", flight: Flight4, serverMKI: "other", hookMKI: finalMKI, wantError: true},
		{name: "resumption", flight: Flight4b, serverMKI: finalMKI, wantMKI: finalMKI},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := newSRTPServerState12()
			if test.flight == Flight4b {
				state.LocalVerifyData = []byte{1}
			}
			recordCH12(t, &state.RemoteClientHelloSnapshots, srtpOffer12(profile80, initialMKI))
			recordCH12(t, &state.RemoteClientHelloSnapshots, srtpOffer12(profile32, finalMKI))

			cfg := &dtlsconfig.HandshakeConfig{
				LocalSRTPProtectionProfiles:  []extension.SRTPProtectionProfile{profile80, profile32},
				LocalSRTPMasterKeyIdentifier: []byte(test.serverMKI),
			}
			if test.hookMKI != "" {
				cfg.ServerHelloMessageHook = func(serverHello handshake.MessageServerHello) handshake.Message {
					serverHello.Extensions = []extension.Value{&extension.SRTPSelection{
						ProtectionProfile: profile32, MasterKeyIdentifier: []byte(test.hookMKI),
					}}

					return &serverHello
				}
			}

			packets, _, err := generateForTest(t, test.flight, nil, state, dtlsflight.NewCache(), cfg)
			if test.wantError {
				require.ErrorIs(t, err, dtlserrors.ErrInvalidServerHello)
				assert.Zero(t, state.SRTPProtectionProfile())

				return
			}
			require.NoError(t, err)
			selection := serverHelloSRTPSelection12(t, packets)
			require.NotNil(t, selection)
			assert.Equal(t, profile32, selection.ProtectionProfile)
			assert.Equal(t, test.wantMKI, string(selection.MasterKeyIdentifier))
			assert.Equal(t, profile32, state.SRTPProtectionProfile())
			assert.Equal(t, finalMKI, string(state.RemoteSRTPMasterKeyIdentifier))
		})
	}
}

func TestFlight12ResumptionClearsStaleSRTPWithoutFinalOffer(t *testing.T) {
	state := newSRTPServerState12()
	state.LocalVerifyData = []byte{1}
	state.SetSRTPProtectionProfile(profile80)
	state.RemoteSRTPMasterKeyIdentifier = []byte("stale")
	recordCH12(t, &state.RemoteClientHelloSnapshots, srtpOffer12(profile80, initialMKI))
	recordCH12(t, &state.RemoteClientHelloSnapshots)

	packets, _, err := generateForTest(t, Flight4b, nil, state, dtlsflight.NewCache(), &dtlsconfig.HandshakeConfig{
		LocalSRTPProtectionProfiles: []extension.SRTPProtectionProfile{profile80},
	})
	require.NoError(t, err)
	assert.Nil(t, serverHelloSRTPSelection12(t, packets))
	assert.Zero(t, state.SRTPProtectionProfile())
}

func TestFlight12ClientValidatesFinalSRTPOfferBeforeCommit(t *testing.T) {
	for _, test := range []struct {
		name, mki string
		profile   extension.SRTPProtectionProfile
		complete  bool
	}{
		{name: "profile not in final offer", profile: profile80, mki: finalMKI},
		{name: "mismatched MKI", profile: profile32, mki: "other"},
		{name: "valid but incomplete flight", profile: profile32, mki: finalMKI},
		{name: "valid complete flight commits", profile: profile32, mki: finalMKI, complete: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, cache, cfg := newSRTPClientFlight3Test(t, test.profile, test.mki)
			if test.complete {
				pushHandshake12(t, cache, 1, &handshake.MessageServerHelloDone{})
			}

			_, _, err := parseForTest(t, Flight3, t.Context(), nil, state, cache, cfg)
			if test.profile != profile32 || test.mki != finalMKI {
				require.ErrorIs(t, err, dtlserrors.ErrClientNoMatchingSRTPProfile)
			} else {
				require.NoError(t, err)
			}
			if test.complete {
				assert.Equal(t, test.profile, state.SRTPProtectionProfile())
				assert.Equal(t, test.mki, string(state.RemoteSRTPMasterKeyIdentifier))
			} else {
				assert.Zero(t, state.SRTPProtectionProfile())
			}
		})
	}
}

func newSRTPServerState12() *dtlsstate.State12 {
	state := newTestState12()
	state.CipherSuite = ciphersuite.ForID(ciphersuite.TLS_PSK_WITH_AES_128_GCM_SHA256, nil)

	return state
}

func newSRTPClientFlight3Test(
	t *testing.T,
	profile extension.SRTPProtectionProfile,
	mki string,
) (*dtlsstate.State12, *dtlsflight.Cache, *dtlsconfig.HandshakeConfig) {
	t.Helper()
	state := newTestState12()
	state.IsClient = true
	suite := ciphersuite.ForID(ciphersuite.TLS_PSK_WITH_AES_128_GCM_SHA256, nil)
	cfg := &dtlsconfig.HandshakeConfig{
		LocalCipherSuites:    []dtlsconfig.CipherSuite{suite},
		LocalPSKIdentityHint: []byte("client"),
		LocalPSKCallback:     func([]byte) ([]byte, error) { return []byte("psk"), nil },
		LocalSRTPProtectionProfiles: []extension.SRTPProtectionProfile{
			profile80, profile32,
		},
		Log: logging.NewDefaultLoggerFactory().NewLogger("dtls"),
	}
	recordCH12(t, &state.LocalClientHelloSnapshots, srtpOffer12(profile80, initialMKI))
	recordCH12(t, &state.LocalClientHelloSnapshots, srtpOffer12(profile32, finalMKI))
	cipherSuiteID := uint16(suite.ID())
	cache := dtlsflight.NewCache()
	pushHandshake12(t, cache, 0, &handshake.MessageServerHello{
		Version: protocol.Version1_2, CipherSuiteID: &cipherSuiteID,
		CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
		Extensions: []extension.Value{&extension.SRTPSelection{
			ProtectionProfile: profile, MasterKeyIdentifier: []byte(mki),
		}},
	})

	return state, cache, cfg
}

func srtpOffer12(profile extension.SRTPProtectionProfile, mki string) *extension.SRTPOffer {
	return &extension.SRTPOffer{
		ProtectionProfiles:  []extension.SRTPProtectionProfile{profile},
		MasterKeyIdentifier: []byte(mki),
	}
}

func pushHandshake12(t *testing.T, cache *dtlsflight.Cache, sequence uint16, message handshake.Message) {
	t.Helper()
	raw, err := (&handshake.Handshake{
		Header: handshake.Header{MessageSequence: sequence}, Message: message,
	}).Marshal()
	require.NoError(t, err)
	cache.Push(raw, 0, sequence, message.Type(), false)
}

func serverHelloSRTPSelection12(t *testing.T, packets []*dtlsflight.Packet) *extension.SRTPSelection {
	t.Helper()
	require.NotEmpty(t, packets)
	handshakePacket, ok := packets[0].Record.Content.(*handshake.Handshake)
	require.True(t, ok)
	serverHello, ok := handshakePacket.Message.(*handshake.MessageServerHello)
	require.True(t, ok)
	for _, value := range serverHello.Extensions {
		if selection, ok := value.(*extension.SRTPSelection); ok {
			return selection
		}
	}

	return nil
}
