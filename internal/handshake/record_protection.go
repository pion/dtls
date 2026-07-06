// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
)

func InitHandshakeRecordProtection(state *dtlsstate.State) error {
	if state == nil || state.CipherSuite == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}

	tls13CipherSuite, ok := state.CipherSuite.(ciphersuite.CipherSuiteTLS13)
	if !ok {
		return dtlserrors.ErrInvalidCipherSuite
	}
	if tls13CipherSuite.IsInitialized() {
		return nil
	}

	secrets := state.HandshakeTrafficSecrets13
	if len(secrets.Client) == 0 || len(secrets.Server) == 0 {
		return dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}

	return tls13CipherSuite.InitFromTrafficSecrets(
		secrets.Client,
		secrets.Server,
		state.IsClient,
	)
}
