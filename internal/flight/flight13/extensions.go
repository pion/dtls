// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"fmt"

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
	val extension.Extension,
) {
	switch ext := val.(type) {
	case *extension.ServerName:
		state.ServerName = ext.ServerName // remote server name
	case *extension.ALPN:
		state.PeerSupportedProtocols = ext.ProtocolNameList
	case *extension.SignatureAlgorithmsCert:
		// Store the client's certificate signature schemes for later validation.
		state.RemoteCertSignatureSchemes = ext.SignatureHashAlgorithms
	case *extension.KeyShare:
		state.RemoteKeyEntries = ext.ClientShares
		state.HasRemoteKeyEntries = true
	}
}

// connectionIDExtension extracts a connection_id extension while preserving
// the distinction between an absent extension and a present, zero-length CID.
func connectionIDExtension(extensions []extension.Extension) ([]byte, bool, bool) {
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
	message handshake.Message,
) error {
	clientHello, ok := message.(*handshake.MessageClientHello)
	if !ok {
		state.SetLocalConnectionID(nil)
		state.LocalCIDOffered = false

		return nil
	}

	localCID, present, duplicate := connectionIDExtension(clientHello.Extensions)
	if duplicate {
		state.SetLocalConnectionID(nil)
		state.LocalCIDOffered = false

		return dtlserrors.ErrInvalidClientHello
	}
	if !present {
		state.SetLocalConnectionID(nil)
		state.LocalCIDOffered = false

		return nil
	}

	state.SetLocalConnectionID(localCID)
	state.LocalCIDOffered = true

	return nil
}

func validateRepeatedClientHelloConnectionIDOffer(
	state *dtlsstate.State13,
	message handshake.Message,
) error {
	clientHello, ok := message.(*handshake.MessageClientHello)
	if !ok {
		state.SetLocalConnectionID(nil)
		state.LocalCIDOffered = false

		return nil
	}

	localCID, present, duplicate := connectionIDExtension(clientHello.Extensions)
	expectedCID := state.LocalConnectionID()
	expectedPresent := state.LocalCIDOffered
	if duplicate {
		return fmt.Errorf("%w: duplicate connection_id extension", dtlserrors.ErrInvalidClientHello)
	}
	if present != expectedPresent {
		return fmt.Errorf("%w: unexpected connection_id extension", dtlserrors.ErrInvalidClientHello)
	}
	if !bytes.Equal(localCID, expectedCID) {
		return fmt.Errorf("%w: unexpected connection_id value", dtlserrors.ErrInvalidClientHello)
	}

	return nil
}
