// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"fmt"
	"slices"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
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
	remoteCID, hasRemoteCID, duplicateCID := connectionIDExtension(clientHello.Extensions)
	if duplicateCID {
		return newClientHelloExtensionFailure(alert.IllegalParameter, dtlserrors.ErrInvalidClientHello)
	}

	for _, val := range clientHello.Extensions {
		if failure := processClientHelloSecurityExtension(state, cfg, &seen, val); failure != nil {
			return failure
		}
		processClientHelloStateExtension(state, val)
	}

	if !seen.hasPreSharedKey && (!seen.hasSignatureAlgorithms || !seen.hasSupportedGroups) {
		return newClientHelloExtensionFailure(alert.MissingExtension, dtlserrors.ErrMissingClientHelloExtension)
	}
	if hasRemoteCID {
		state.RemoteConnectionID = remoteCID
	} else {
		state.RemoteConnectionID = nil
	}
	state.RemoteCIDOffered = hasRemoteCID

	return nil
}

func processClientHelloSecurityExtension(
	state *dtlsstate.State13,
	cfg *dtlsconfig.HandshakeConfig,
	seen *clientHelloExtensionSet,
	val extension.Value,
) *clientHelloExtensionFailure {
	switch ext := val.(type) {
	case *extension.SupportedGroups:
		seen.hasSupportedGroups = true
		if len(ext.Groups) == 0 {
			return newClientHelloExtensionFailure(alert.InsufficientSecurity, dtlserrors.ErrNoSupportedEllipticCurves)
		}
		state.RemoteGroups = slices.Clone(ext.Groups)
	case *extension.SRTPOffer:
		profile, ok := dtlsflight.FindMatchingSRTPProfile(cfg.LocalSRTPProtectionProfiles, ext.ProtectionProfiles)
		if !ok {
			return newClientHelloExtensionFailure(alert.InsufficientSecurity, dtlserrors.ErrServerNoMatchingSRTPProfile)
		}
		state.SetSRTPProtectionProfile(profile)
		state.RemoteSRTPMasterKeyIdentifier = bytes.Clone(ext.MasterKeyIdentifier)
	case *extension.SignatureAlgorithms:
		seen.hasSignatureAlgorithms = true
		state.RemoteSignatureSchemes = dtlsflight.SignatureSchemes(ext.Schemes)
	case *extension13.OfferedVersions:
		state.RemoteVersions = slices.Clone(ext.Versions)
	case *extension13.OfferedPSKs:
		seen.hasPreSharedKey = true
	}

	return nil
}

func processClientHelloStateExtension(
	state *dtlsstate.State13,
	val extension.Value,
) {
	switch ext := val.(type) {
	case *extension.ServerNameOffer:
		state.ServerName = ext.ServerName // remote server name
	case *extension.ALPNOffer:
		state.PeerSupportedProtocols = slices.Clone(ext.Protocols)
	case *extension.CertificateSignatureAlgorithms:
		// Store the client's certificate signature schemes for later validation.
		state.RemoteCertSignatureSchemes = dtlsflight.SignatureSchemes(ext.Schemes)
	case *extension13.ClientKeyShare:
		state.RemoteKeyEntries = cloneKeyShareEntries(ext.Shares)
		state.HasRemoteKeyEntries = true
	}
}

func cloneKeyShareEntries(entries []extension13.KeyShareEntry) []extension13.KeyShareEntry {
	cloned := make([]extension13.KeyShareEntry, len(entries))
	for i := range entries {
		cloned[i] = entries[i]
		cloned[i].KeyExchange = bytes.Clone(entries[i].KeyExchange)
	}

	return cloned
}

// connectionIDExtension extracts a connection_id extension while preserving
// the distinction between an absent extension and a present, zero-length CID.
func connectionIDExtension(extensions []extension.Value) ([]byte, bool, bool) {
	var cid []byte
	found := false
	for _, val := range extensions {
		ext, ok := val.(*extension.ConnectionID)
		if !ok {
			continue
		}
		if found {
			return nil, false, true
		}
		if len(ext.CID) > 0 {
			cid = bytes.Clone(ext.CID)
		}
		found = true
	}

	return cid, found, false
}

func captureClientHelloConnectionIDOffer(
	state *dtlsstate.State13,
	clientHello *handshake.MessageClientHello,
) {
	localCID, present, _ := connectionIDExtension(clientHello.Extensions)
	state.SetLocalConnectionID(localCID)
	state.LocalCIDOffered = present
}

func validateRepeatedClientHelloConnectionIDOffer(
	state *dtlsstate.State13,
	clientHello *handshake.MessageClientHello,
) error {
	localCID, present, _ := connectionIDExtension(clientHello.Extensions)
	if present != state.LocalCIDOffered || !bytes.Equal(localCID, state.LocalConnectionID()) {
		return fmt.Errorf("%w: connection_id changed", dtlserrors.ErrInvalidClientHello)
	}

	return nil
}
