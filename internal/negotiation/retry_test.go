// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package negotiation

import (
	"slices"
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secondUnknownExtensionType extension.Type = 0xfefd

func retryClientHelloForTest(withEarlyData bool) *handshake.MessageClientHello {
	clientHello := clientHelloForTest(
		&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519, elliptic.P256}},
		&extension13.ClientKeyShare{Shares: []extension13.KeyShareEntry{{
			Group: elliptic.P256, KeyExchange: []byte{0x04, 0x01},
		}}},
		extension.Raw{Type: unknownExtensionType, Data: []byte{0x01}},
		extension.Raw{Type: secondUnknownExtensionType, Data: []byte{0x02}},
	)
	clientHello.CipherSuiteIDs = []uint16{0x1301, 0x1302}
	clientHello.CompressionMethods = []*protocol.CompressionMethod{{ID: 0}, {ID: 0}}
	clientHello.Random.RandomBytes[0] = 0xaa
	if withEarlyData {
		clientHello.SetExtensions(append(clientHello.Extensions(),
			&extension13.PSKKeyExchangeModes{
				Modes: []extension13.PSKKeyExchangeMode{extension13.PSKDHEKE},
			},
			&extension13.EarlyData{},
			&extension13.OfferedPSKs{
				Identities: []extension13.PSKIdentity{{Identity: []byte("ticket")}},
				Binders:    []extension13.PSKBinder{make([]byte, 32)},
			},
		))
	}

	return clientHello
}

func snapshotClientHelloForRetryTest(t *testing.T, clientHello *handshake.MessageClientHello) ClientHelloSnapshot {
	t.Helper()
	_, snapshot, err := FinalizeClientHello(clientHello, nil)
	require.NoError(t, err)

	return snapshot
}

func helloRetryRequest13ForTest(
	cipherSuiteID uint16,
	selectedGroup *elliptic.Curve,
	cookie []byte,
) *handshake.MessageServerHello {
	exts := []extension.Value{&extension13.SelectedVersion{Version: protocol.Version1_3}}
	if selectedGroup != nil {
		exts = append(exts, &extension13.RetryKeyShare{SelectedGroup: *selectedGroup})
	}
	if cookie != nil {
		exts = append(exts, &extension13.Cookie{Cookie: cookie})
	}
	hrr := helloRetryRequestForTest(exts...)
	hrr.CipherSuiteID = &cipherSuiteID

	return hrr
}

func finalizedRetryForTest(
	t *testing.T,
	initial ClientHelloSnapshot,
	request RetryRequest,
) ClientHelloSnapshot {
	t.Helper()
	var freshShare *extension13.KeyShareEntry
	if request.HasSelectedGroup {
		freshShare = &extension13.KeyShareEntry{Group: request.SelectedGroup, KeyExchange: []byte{0x11, 0x22}}
	}
	clientHello, err := BuildClientHelloRetry(initial, request, freshShare)
	require.NoError(t, err)
	_, snapshot, err := FinalizeClientHello(clientHello, nil)
	require.NoError(t, err)

	return snapshot
}

func mutateSnapshotForRetryTest(
	t *testing.T,
	snapshot ClientHelloSnapshot,
	mutate func(*handshake.MessageClientHello),
) ClientHelloSnapshot {
	t.Helper()
	clientHello, err := ClientHelloFromSnapshot(snapshot)
	require.NoError(t, err)
	mutate(clientHello)

	return snapshotClientHelloForRetryTest(t, clientHello)
}

func replaceRetryExtension(
	clientHello *handshake.MessageClientHello, typ extension.Type, replacement extension.Value,
) {
	for i, value := range clientHello.Extensions() {
		if value.ExtensionType() == typ {
			extensions := clientHello.Extensions()
			extensions[i] = replacement
			clientHello.SetExtensions(extensions)
		}
	}
}

func TestValidateHelloRetryRequest13(t *testing.T) {
	initial := snapshotClientHelloForRetryTest(t, retryClientHelloForTest(false))
	selected := elliptic.X25519

	for name, test := range map[string]struct {
		hrr       *handshake.MessageServerHello
		wantError bool
	}{
		"selected group and cookie": {hrr: helloRetryRequest13ForTest(0x1301, &selected, []byte("cookie"))},
		"cookie only":               {hrr: helloRetryRequest13ForTest(0x1301, nil, []byte("cookie"))},
		"selected group only":       {hrr: helloRetryRequest13ForTest(0x1301, &selected, nil)},
		"unoffered cipher suite":    {hrr: helloRetryRequest13ForTest(0x1303, nil, []byte("cookie")), wantError: true},
		"unsupported selected group": {
			hrr: helloRetryRequest13ForTest(0x1301, ptrRetryGroup(elliptic.P384), nil), wantError: true,
		},
		"group already shared": {
			hrr: helloRetryRequest13ForTest(0x1301, ptrRetryGroup(elliptic.P256), nil), wantError: true,
		},
		"no effect": {hrr: helloRetryRequest13ForTest(0x1301, nil, nil), wantError: true},
	} {
		t.Run(name, func(t *testing.T) {
			request, err := ValidateHelloRetryRequest(initial, test.hrr)
			if !test.wantError {
				require.NoError(t, err)
				assert.True(t, request.valid)

				return
			}
			require.ErrorIs(t, err, dtlserrors.ErrInvalidHelloRetryRequest)
			requireAlert(t, err, alert.IllegalParameter)
			assert.False(t, request.valid)
		})
	}
}

func ptrRetryGroup(group elliptic.Curve) *elliptic.Curve { return &group }

func TestValidateClientHelloRetryMatrix(t *testing.T) { //nolint:maintidx
	initial := snapshotClientHelloForRetryTest(t, retryClientHelloForTest(true))
	selected := elliptic.X25519
	request, err := ValidateHelloRetryRequest(
		initial, helloRetryRequest13ForTest(0x1301, &selected, []byte("cookie")),
	)
	require.NoError(t, err)
	validRetry := finalizedRetryForTest(t, initial, request)

	tests := map[string]struct {
		mutate func(*handshake.MessageClientHello)
		valid  bool
	}{
		"authorized changes": {valid: true},
		"padding change": {
			valid: true,
			mutate: func(ch *handshake.MessageClientHello) {
				ch.SetExtensions(slices.Insert(ch.Extensions(), 2,
					extension.Value(
						extension.Raw{
							Type: extension.TypePadding,
							Data: []byte{0x00, 0x00},
						},
					)))
			},
		},
		"version": {mutate: func(ch *handshake.MessageClientHello) {
			ch.Version = protocol.Version1_0
		}},
		"random": {mutate: func(ch *handshake.MessageClientHello) {
			ch.Random.RandomBytes[0] ^= 0xff
		}},
		"session ID": {mutate: func(ch *handshake.MessageClientHello) {
			ch.SessionID = []byte{0xff}
		}},
		"cipher suites": {mutate: func(ch *handshake.MessageClientHello) {
			ch.CipherSuiteIDs = slices.Clone(ch.CipherSuiteIDs[:1])
		}},
		"compression methods": {mutate: func(ch *handshake.MessageClientHello) {
			ch.CompressionMethods = ch.CompressionMethods[:1]
		}},
		"unknown payload": {mutate: func(ch *handshake.MessageClientHello) {
			replaceRetryExtension(ch, unknownExtensionType,
				extension.Raw{Type: unknownExtensionType, Data: []byte{0xff}})
		}},
		"unknown order": {mutate: func(ch *handshake.MessageClientHello) {
			first, second := -1, -1
			for i, value := range ch.Extensions() {
				if value.ExtensionType() == unknownExtensionType {
					first = i
				} else if value.ExtensionType() == secondUnknownExtensionType {
					second = i
				}
			}
			extensions := ch.Extensions()
			extensions[first], extensions[second] = extensions[second], extensions[first]
			ch.SetExtensions(extensions)
		}},
		"supported groups": {mutate: func(ch *handshake.MessageClientHello) {
			replaceRetryExtension(ch, extension.TypeSupportedGroups,
				&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}})
		}},
		"missing cookie": {mutate: func(ch *handshake.MessageClientHello) {
			ch.SetExtensions(slices.DeleteFunc(ch.Extensions(), func(value extension.Value) bool {
				return value.ExtensionType() == extension.TypeCookie
			}))
		}},
		"wrong cookie": {mutate: func(ch *handshake.MessageClientHello) {
			replaceRetryExtension(ch, extension.TypeCookie, &extension13.Cookie{Cookie: []byte("wrong")})
		}},
		"wrong share": {mutate: func(ch *handshake.MessageClientHello) {
			replaceRetryExtension(ch, extension.TypeKeyShare, &extension13.ClientKeyShare{
				Shares: []extension13.KeyShareEntry{{Group: elliptic.P256, KeyExchange: []byte{0x01}}},
			})
		}},
		"multiple shares": {mutate: func(ch *handshake.MessageClientHello) {
			replaceRetryExtension(ch, extension.TypeKeyShare, &extension13.ClientKeyShare{
				Shares: []extension13.KeyShareEntry{
					{Group: elliptic.X25519, KeyExchange: []byte{0x01}},
					{Group: elliptic.P256, KeyExchange: []byte{0x02}},
				},
			})
		}},
		"early data retained": {mutate: func(ch *handshake.MessageClientHello) {
			ch.SetExtensions(slices.Insert(
				ch.Extensions(), len(ch.Extensions())-1, extension.Value(&extension13.EarlyData{}),
			))
		}},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			retry := validRetry
			if test.mutate != nil {
				retry = mutateSnapshotForRetryTest(t, retry, test.mutate)
			}
			err := ValidateClientHelloRetry(initial, retry, request)
			if test.valid {
				require.NoError(t, err)

				return
			}
			require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
			requireAlert(t, err, alert.IllegalParameter)
		})
	}
}

func TestValidateClientHelloRetryCookieOnlyKeepsKeyShare(t *testing.T) {
	initial := snapshotClientHelloForRetryTest(t, retryClientHelloForTest(false))
	request, err := ValidateHelloRetryRequest(
		initial, helloRetryRequest13ForTest(0x1301, nil, []byte("cookie")),
	)
	require.NoError(t, err)
	retry := finalizedRetryForTest(t, initial, request)
	require.NoError(t, ValidateClientHelloRetry(initial, retry, request))

	retry = mutateSnapshotForRetryTest(t, retry, func(ch *handshake.MessageClientHello) {
		replaceRetryExtension(ch, extension.TypeKeyShare, &extension13.ClientKeyShare{
			Shares: []extension13.KeyShareEntry{{Group: elliptic.P256, KeyExchange: []byte{0xff}}},
		})
	})
	require.ErrorIs(t, ValidateClientHelloRetry(initial, retry, request), dtlserrors.ErrInvalidClientHello)
}

func TestValidateHelloVerifyRequestResponse(t *testing.T) {
	initialHello := retryClientHelloForTest(false)
	initialHello.SetExtensions(append(initialHello.Extensions(),
		&extension.ConnectionID{CID: []byte{0x01}},
		&extension.SRTPOffer{ProtectionProfiles: []extension.SRTPProtectionProfile{extension.SRTP_AEAD_AES_128_GCM}},
	))
	initial := snapshotClientHelloForRetryTest(t, initialHello)
	retryHello, err := ClientHelloFromSnapshot(initial)
	require.NoError(t, err)
	retryHello.Cookie = []byte("cookie")
	retryExtensions := retryHello.Extensions()
	retryExtensions[2] = extension.Raw{Type: unknownExtensionType, Data: []byte{0xff}}
	retryHello.SetExtensions(retryExtensions)
	retry := snapshotClientHelloForRetryTest(t, retryHello)

	tests := map[string]struct {
		mutate    func(*handshake.MessageClientHello)
		wantError bool
	}{
		"DTLS 1.2 extension changes allowed": {},
		"version": {
			mutate: func(ch *handshake.MessageClientHello) { ch.Version = protocol.Version1_0 }, wantError: true,
		},
		"random": {
			mutate: func(ch *handshake.MessageClientHello) { ch.Random.RandomBytes[0] ^= 0xff }, wantError: true,
		},
		"session ID": {
			mutate: func(ch *handshake.MessageClientHello) { ch.SessionID = []byte{0xff} }, wantError: true,
		},
		"cipher suites": {
			mutate: func(ch *handshake.MessageClientHello) { ch.CipherSuiteIDs = ch.CipherSuiteIDs[:1] }, wantError: true,
		},
		"compression": {
			mutate: func(ch *handshake.MessageClientHello) {
				ch.CompressionMethods = ch.CompressionMethods[:1]
			},
			wantError: true,
		},
		"cookie": {
			mutate: func(ch *handshake.MessageClientHello) { ch.Cookie = []byte("wrong") }, wantError: true,
		},
		"connection ID": {mutate: func(ch *handshake.MessageClientHello) {
			replaceRetryExtension(ch, extension.TypeConnectionID, &extension.ConnectionID{CID: []byte{0xff}})
		}, wantError: true},
		"use_srtp": {mutate: func(ch *handshake.MessageClientHello) {
			replaceRetryExtension(ch, extension.TypeUseSRTP, &extension.SRTPOffer{
				ProtectionProfiles: []extension.SRTPProtectionProfile{extension.SRTP_AEAD_AES_256_GCM},
			})
		}, wantError: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := retry
			if test.mutate != nil {
				candidate = mutateSnapshotForRetryTest(t, retry, test.mutate)
			}
			err := ValidateHelloVerifyRequestResponse(initial, candidate, []byte("cookie"))
			if !test.wantError {
				require.NoError(t, err)

				return
			}
			require.ErrorIs(t, err, dtlserrors.ErrInvalidClientHello)
			requireAlert(t, err, alert.IllegalParameter)
		})
	}
}

func TestValidateServerHelloAfterRetry(t *testing.T) {
	initial := snapshotClientHelloForRetryTest(t, retryClientHelloForTest(false))
	selected := elliptic.X25519
	request, err := ValidateHelloRetryRequest(
		initial, helloRetryRequest13ForTest(0x1301, &selected, nil),
	)
	require.NoError(t, err)

	serverHello := func(cipherSuite uint16, share *extension13.ServerKeyShare) *handshake.MessageServerHello {
		exts := []extension.Value{&extension13.SelectedVersion{Version: protocol.Version1_3}}
		if share != nil {
			exts = append(exts, share)
		}

		return withExtensions(&handshake.MessageServerHello{CipherSuiteID: &cipherSuite}, exts)
	}
	validShare := &extension13.ServerKeyShare{Share: extension13.KeyShareEntry{
		Group: elliptic.X25519, KeyExchange: []byte{0x01},
	}}
	invalidRequestErr := ValidateServerHelloAfterRetry(RetryRequest{}, serverHello(0x1301, validShare))
	require.ErrorIs(t, invalidRequestErr, dtlserrors.ErrInvalidServerHello)
	requireAlert(t, invalidRequestErr, alert.IllegalParameter)

	for name, test := range map[string]struct {
		serverHello *handshake.MessageServerHello
		wantError   error
	}{
		"valid":                {serverHello: serverHello(0x1301, validShare)},
		"changed cipher suite": {serverHello: serverHello(0x1302, validShare), wantError: dtlserrors.ErrInvalidServerHello},
		"missing share":        {serverHello: serverHello(0x1301, nil), wantError: dtlserrors.ErrServerKeyShareMissing},
		"wrong group": {serverHello: serverHello(0x1301, &extension13.ServerKeyShare{Share: extension13.KeyShareEntry{
			Group: elliptic.P256, KeyExchange: []byte{0x01},
		}}), wantError: dtlserrors.ErrServerKeyShareUnknownGroup},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateServerHelloAfterRetry(request, test.serverHello)
			if test.wantError == nil {
				require.NoError(t, err)

				return
			}
			require.ErrorIs(t, err, dtlserrors.ErrInvalidServerHello)
			require.ErrorIs(t, err, test.wantError)
			requireAlert(t, err, alert.IllegalParameter)
		})
	}
}
