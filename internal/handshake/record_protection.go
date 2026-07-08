// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
)

func InitHandshakeRecordProtection(state *dtlsstate.State13) error {
	if state == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}

	return initRecordProtectionFromTrafficSecrets(state, state.KeySchedule.HandshakeTraffic, false)
}

// InitApplicationRecordProtection installs DTLS 1.3 application record
// protection from the stored application traffic secrets.
func InitApplicationRecordProtection(state *dtlsstate.State13) error {
	if state == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}

	return initRecordProtectionFromTrafficSecrets(state, dtlsstate.TrafficSecrets{
		Client: state.KeySchedule.ClientApplicationTrafficSecret0,
		Server: state.KeySchedule.ServerApplicationTrafficSecret0,
	}, true)
}

func initRecordProtectionFromTrafficSecrets(
	state *dtlsstate.State13,
	secrets dtlsstate.TrafficSecrets,
	allowReinitialize bool,
) error {
	if state == nil || state.CipherSuite == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}

	tls13CipherSuite, ok := state.CipherSuite.(ciphersuite.CipherSuiteTLS13)
	if !ok {
		return dtlserrors.ErrInvalidCipherSuite
	}
	if !allowReinitialize && tls13CipherSuite.IsInitialized() {
		return nil
	}

	if len(secrets.Client) == 0 || len(secrets.Server) == 0 {
		return dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	return tls13CipherSuite.InitFromTrafficSecrets(
		secrets.Client,
		secrets.Server,
		state.IsClient,
	)
}
