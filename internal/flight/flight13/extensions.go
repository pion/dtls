// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"slices"

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
	clientHello *handshake.MessageClientHello,
) *clientHelloExtensionFailure {
	var seen clientHelloExtensionSet

	for _, val := range clientHello.Extensions {
		if failure := processClientHelloSecurityExtension(state, &seen, val); failure != nil {
			return failure
		}
		processClientHelloStateExtension(state, val)
	}

	if !seen.hasPreSharedKey && (!seen.hasSignatureAlgorithms || !seen.hasSupportedGroups) {
		return newClientHelloExtensionFailure(alert.MissingExtension, dtlserrors.ErrMissingClientHelloExtension)
	}

	return nil
}

func processClientHelloSecurityExtension(
	state *dtlsstate.State13,
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
