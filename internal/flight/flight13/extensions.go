// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

type clientHelloExtensionSet struct {
	hasPreSharedKey        bool
	hasSignatureAlgorithms bool
	hasSupportedGroups     bool
}

type clientHelloExtensionFailure struct {
	alert *alert.Alert
	err   error
}

func newClientHelloExtensionFailure(
	description alert.Description,
	err error,
) *clientHelloExtensionFailure {
	return &clientHelloExtensionFailure{
		alert: &alert.Alert{Level: alert.Fatal, Description: description},
		err:   err,
	}
}

func processClientHelloExtensions(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
	clientHello *handshake.MessageClientHello,
) *clientHelloExtensionFailure {
	var seen clientHelloExtensionSet

	for _, val := range clientHello.Extensions {
		if failure := processClientHelloSecurityExtension(state, cfg, &seen, val); failure != nil {
			return failure
		}
		processClientHelloStateExtension(state, cfg, val)
	}

	if !seen.hasPreSharedKey && (!seen.hasSignatureAlgorithms || !seen.hasSupportedGroups) {
		return newClientHelloExtensionFailure(alert.MissingExtension, dtlserrors.ErrMissingClientHelloExtension)
	}

	return nil
}

func processClientHelloSecurityExtension(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
	seen *clientHelloExtensionSet,
	val extension.Extension,
) *clientHelloExtensionFailure {
	switch ext := val.(type) {
	case *extension.SupportedEllipticCurves:
		seen.hasSupportedGroups = true
		if len(ext.EllipticCurves) == 0 {
			return newClientHelloExtensionFailure(alert.InsufficientSecurity, dtlserrors.ErrNoSupportedEllipticCurves)
		}
		state.RemoteGroups = ext.EllipticCurves
	case *extension.UseSRTP:
		profile, ok := dtlsflight.FindMatchingSRTPProfile(cfg.LocalSRTPProtectionProfiles, ext.ProtectionProfiles)
		if !ok {
			return newClientHelloExtensionFailure(alert.InsufficientSecurity, dtlserrors.ErrServerNoMatchingSRTPProfile)
		}
		state.SetSRTPProtectionProfile(profile)
		state.RemoteSRTPMasterKeyIdentifier = ext.MasterKeyIdentifier
	case *extension.SupportedSignatureAlgorithms:
		seen.hasSignatureAlgorithms = true
		state.RemoteSignatureSchemes = ext.SignatureHashAlgorithms
	case *extension.SupportedVersions:
		if ext.IsSelectedVersion() {
			return newClientHelloExtensionFailure(alert.IllegalParameter, dtlserrors.ErrInvalidClientHello)
		}
		state.RemoteVersions = ext.Versions
	case *extension.PreSharedKey:
		seen.hasPreSharedKey = true
	}

	return nil
}

func processClientHelloStateExtension(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
	val extension.Extension,
) {
	switch ext := val.(type) {
	case *extension.ServerName:
		state.ServerName = ext.ServerName // remote server name
	case *extension.ALPN:
		state.PeerSupportedProtocols = ext.ProtocolNameList
	case *extension.ConnectionID:
		// Only set connection ID to be sent if server supports connection IDs.
		if cfg.ConnectionIDGenerator != nil {
			state.RemoteConnectionID = ext.CID
		}
	case *extension.SignatureAlgorithmsCert:
		// Store the client's certificate signature schemes for later validation.
		state.RemoteCertSignatureSchemes = ext.SignatureHashAlgorithms
	case *extension.KeyShare:
		state.RemoteKeyEntries = ext.ClientShares
		state.HasRemoteKeyEntries = true
	}
}
