// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"testing"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	srtpProfile13 extension.SRTPProtectionProfile = extension.SRTP_AES128_CM_HMAC_SHA1_80
	srtpMKI13                                     = "client-mki"
)

func TestFlight4GenerateNegotiatesSRTPInEncryptedExtensions(t *testing.T) {
	for _, test := range []struct {
		name, offerMKI, serverMKI, wantMKI string
		offer                              bool
		wantError                          bool
	}{
		{name: "echo", offer: true, offerMKI: srtpMKI13, serverMKI: srtpMKI13, wantMKI: srtpMKI13},
		{name: "decline", offer: true, offerMKI: srtpMKI13, serverMKI: "other"},
		{name: "not offered", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			flightCtx := flight4TestContext(t)
			flightCtx.cfg.LocalSRTPProtectionProfiles = []extension.SRTPProtectionProfile{srtpProfile13}
			flightCtx.cfg.LocalSRTPMasterKeyIdentifier = []byte(test.serverMKI)
			if test.offer {
				flightCtx.state.RemoteClientHelloSnapshots.Reset()
				require.NoError(t, flightCtx.state.RemoteClientHelloSnapshots.Record(
					srtpSnapshot13(t, srtpProfile13, test.offerMKI),
				))
			}

			packets, _, err := flight4Generate(nil, flightCtx)
			if test.wantError {
				require.ErrorIs(t, err, dtlserrors.ErrServerNoMatchingSRTPProfile)
				assert.Nil(t, packets)
				assert.Zero(t, flightCtx.state.SRTPProtectionProfile())

				return
			}
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(packets), 2)
			serverHello := packets[0].Content.(*handshake.Handshake).Message.(*handshake.MessageServerHello) //nolint:forcetypeassert,lll
			assert.False(t, hasSRTPSelection13(serverHello.Extensions()))
			encryptedExtensions := packets[1].Content.(*handshake.Handshake).Message.(*handshake.MessageEncryptedExtensions) //nolint:forcetypeassert,lll
			selection := findSRTPSelection13(encryptedExtensions.Extensions())
			require.NotNil(t, selection)
			assert.Equal(t, srtpProfile13, selection.ProtectionProfile)
			assert.Equal(t, test.wantMKI, string(selection.MasterKeyIdentifier))
			assert.Equal(t, srtpProfile13, flightCtx.state.SRTPProtectionProfile())
			assert.Equal(t, test.offerMKI, string(flightCtx.state.RemoteSRTPMasterKeyIdentifier))
		})
	}
}

func TestFlight3ParseValidatesAndRollsBackSRTP(t *testing.T) {
	laterFailure := dtlserrors.ErrInvalidCertificate
	for _, test := range []struct {
		name       string
		extensions []extension.Value
		handlerErr error
		wantError  error
		wantCommit bool
	}{
		{
			name: "valid",
			extensions: []extension.Value{&extension.SRTPSelection{
				ProtectionProfile: srtpProfile13, MasterKeyIdentifier: []byte(srtpMKI13),
			}},
			wantCommit: true,
		},
		{
			name: "mismatched MKI",
			extensions: []extension.Value{&extension.SRTPSelection{
				ProtectionProfile: srtpProfile13, MasterKeyIdentifier: []byte("other"),
			}},
			wantError: dtlserrors.ErrClientNoMatchingSRTPProfile,
		},
		{name: "missing selection", wantError: dtlserrors.ErrRequestedButNoSRTPExtension},
		{
			name: "later failure",
			extensions: []extension.Value{&extension.SRTPSelection{
				ProtectionProfile: srtpProfile13, MasterKeyIdentifier: []byte(srtpMKI13),
			}},
			handlerErr: laterFailure,
			wantError:  laterFailure,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := dtlsstate.NewState13(true)
			state.SetRemoteEpoch(EpochHandshake)
			require.NoError(t, state.LocalClientHelloSnapshots.Record(
				srtpSnapshot13(t, srtpProfile13, srtpMKI13),
			))
			cache := dtlsflight.NewCache()
			cache.Push(marshalProtectedTestHandshake(t, 0, &handshake.MessageEncryptedExtensions{
				CachedExtensions: extension.CachedList{Values: test.extensions},
			}), EpochHandshake, 0, handshake.TypeEncryptedExtensions, false)
			cache.Push(marshalProtectedTestHandshake(t, 1, &handshake.MessageFinished{}),
				EpochHandshake, 1, handshake.TypeFinished, false)
			handlerCalled := false
			next, dtlsAlert, err := flight3Parse(t.Context(), nil, &handshakeContext{
				state: &state,
				cache: cache,
				cfg: &dtlsconfig.HandshakeConfig{
					LocalSRTPProtectionProfiles: []extension.SRTPProtectionProfile{srtpProfile13},
				},
				protectedHandshakeHandler: func(
					_ dtlsconfig.CipherSuite,
					_ []dtlsflight.DecodedHandshakeCacheItem,
				) error {
					handlerCalled = true
					assert.Equal(t, srtpProfile13, state.SRTPProtectionProfile())
					assert.Equal(t, srtpMKI13, string(state.RemoteSRTPMasterKeyIdentifier))

					return test.handlerErr
				},
			})
			if test.wantError != nil {
				require.ErrorIs(t, err, test.wantError)
				assert.Zero(t, next)
				assert.Zero(t, state.SRTPProtectionProfile())
				if test.handlerErr == nil {
					assert.False(t, handlerCalled)
				}

				return
			}
			require.NoError(t, err)
			require.Nil(t, dtlsAlert)
			assert.Equal(t, Flight5, next)
			assert.True(t, handlerCalled)
			assert.Equal(t, test.wantCommit, state.SRTPProtectionProfile() != 0)
		})
	}
}

func TestValidateSRTPRetry(t *testing.T) {
	initial := srtpSnapshot13(t, srtpProfile13, srtpMKI13)
	for _, test := range []struct {
		name      string
		retry     negotiation.ClientHelloSnapshot
		wantError bool
	}{
		{name: "identical", retry: srtpSnapshot13(t, srtpProfile13, srtpMKI13)},
		{name: "changed MKI", retry: srtpSnapshot13(t, srtpProfile13, "other"), wantError: true},
		{name: "removed", retry: srtpSnapshot13(t, 0, ""), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := negotiation.ValidateSRTPRetry(initial, test.retry)
			if test.wantError {
				require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
				var dtlsAlert *alert.Alert
				require.ErrorAs(t, err, &dtlsAlert)
				assert.Equal(t, alert.IllegalParameter, dtlsAlert.Description)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestFlight2ParseRejectsChangedSRTPOffer(t *testing.T) {
	state := dtlsstate.NewState13(false)
	state.Cookie = []byte("cookie")
	state.HandshakeRecvSequence = 1
	require.NoError(t, state.RemoteClientHelloSnapshots.Record(
		srtpSnapshot13(t, srtpProfile13, srtpMKI13),
	))
	id := uint16(0x1301)
	request, err := negotiation.ValidateHelloRetryRequest(
		state.RemoteClientHelloSnapshots.Initial(), &handshake.MessageServerHello{
			CipherSuiteID: &id, CachedExtensions: extension.CachedList{
				Values: []extension.Value{
					&extension13.SelectedVersion{Version: protocol.Version1_3},
					&extension13.Cookie{Cookie: state.Cookie},
				},
			},
		})
	require.NoError(t, err)
	state.HelloRetryRequest = request
	message := &handshake.Handshake{
		Header: handshake.Header{MessageSequence: 1},
		Message: &handshake.MessageClientHello{
			Version:        protocol.Version1_2,
			CipherSuiteIDs: []uint16{0x1301},
			CachedExtensions: extension.CachedList{
				Values: []extension.Value{
					&extension13.Cookie{Cookie: state.Cookie},
					&extension.SRTPOffer{
						ProtectionProfiles:  []extension.SRTPProtectionProfile{srtpProfile13},
						MasterKeyIdentifier: []byte("changed"),
					},
				},
			},
		},
	}
	raw, err := message.Marshal()
	require.NoError(t, err)
	cache := dtlsflight.NewCache()
	cache.Push(raw, EpochInitial, 1, handshake.TypeClientHello, true)

	next, dtlsAlert, err := flight2Parse(t.Context(), nil, &handshakeContext{
		state: &state, cache: cache, cfg: &dtlsconfig.HandshakeConfig{},
	})
	require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
	assert.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter}, dtlsAlert)
	assert.Zero(t, next)
}

func srtpSnapshot13(
	t *testing.T,
	profile extension.SRTPProtectionProfile,
	mki string,
) negotiation.ClientHelloSnapshot {
	t.Helper()
	extensions := []extension.Value{}
	if profile != 0 {
		extensions = append(extensions, &extension.SRTPOffer{
			ProtectionProfiles:  []extension.SRTPProtectionProfile{profile},
			MasterKeyIdentifier: []byte(mki),
		})
	}
	_, snapshot, err := negotiation.FinalizeClientHello(
		&handshake.MessageClientHello{
			Version:          protocol.Version1_2,
			CipherSuiteIDs:   []uint16{0x1301},
			CachedExtensions: extension.CachedList{Values: extensions},
		}, nil,
	)
	require.NoError(t, err)

	return snapshot
}

func hasSRTPSelection13(extensions []extension.Value) bool {
	return findSRTPSelection13(extensions) != nil
}

func findSRTPSelection13(extensions []extension.Value) *extension.SRTPSelection {
	for _, value := range extensions {
		if selection, ok := value.(*extension.SRTPSelection); ok {
			return selection
		}
	}

	return nil
}
