// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/fips140"
	"errors"
	"net"
	"slices"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/protocol"
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

	return createConn(conn, rAddr, config, state.isClient, internalState)
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
	apply := Option.applyServer
	if state.isClient {
		apply = Option.applyClient
	}
	config, err := applyOptions(state.isClient, opts, apply)
	if err != nil {
		return nil, err
	}
	version := state.version
	if version == 0 {
		version = protocol.Version1_2
	}
	if config.MinVersion == 0 {
		config.MinVersion = version
	}
	if config.MaxVersion == 0 {
		config.MaxVersion = version
	}
	if !slices.Contains(dtlsconfig.SupportedVersionsRange(config.MinVersion, config.MaxVersion), version) {
		return nil, dtlserrors.ErrUnsupportedProtocolVersion
	}

	return resumeWithConfig(state, conn, rAddr, config)
}
