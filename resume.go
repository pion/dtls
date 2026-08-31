// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/fips140"
	"errors"
	"net"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
)

func resumeWithConfig(state *State, conn net.PacketConn, rAddr net.Addr, config *dtlsConfig) (*Conn, error) {
	if config == nil {
		return nil, dtlserrors.ErrNoConfigProvided
	}
	if state.CipherSuiteID == 0 {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}
	selected, err := resolveResumeCipherSuite(state, config)
	if err != nil {
		return nil, err
	}
	state.cipherSuiteDescriptor = selected

	internalState, err := state.generateInternalState()
	if err != nil {
		return nil, err
	}

	return createConn(conn, rAddr, config, internalState.IsClient, internalState)
}

func resolveResumeCipherSuite(state *State, config *dtlsConfig) (cryptosuite.Suite, error) {
	// Resuming rebuilds the cipher from the stored suite ID, skipping the
	// negotiation-time FIPS filter, so refuse a non-approved suite here.
	if fips140.Enabled() && !cipherSuiteFIPSApproved(state.CipherSuiteID) {
		return nil, dtlserrors.ErrCipherSuiteNotFIPSApproved
	}

	selected, err := state.cipherSuite()
	if err == nil {
		return selected, nil
	}
	if !errors.Is(err, dtlserrors.ErrCipherSuiteNotSet) {
		return nil, err
	}

	configValues, err := newConnConfigValues(config)
	if err != nil {
		return nil, err
	}
	for _, suite := range configValues.cipherSuites {
		if suite.ID() == state.CipherSuiteID {
			return suite, nil
		}
	}

	return nil, &invalidCipherSuiteError{state.CipherSuiteID}
}

// Resume imports an already established dtls connection using a specific dtls state.
func Resume(state *State, conn net.PacketConn, rAddr net.Addr, opts ...Option) (*Conn, error) {
	config, err := buildConfig(opts...)
	if err != nil {
		return nil, err
	}

	return resumeWithConfig(state, conn, rAddr, config)
}
