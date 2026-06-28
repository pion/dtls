// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"net"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func resumeWithConfig(state *State, conn net.PacketConn, rAddr net.Addr, config *dtlsConfig) (*Conn, error) {
	internalState, err := state.generateInternalState()
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, dtlserrors.ErrNoConfigProvided
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return createConn(conn, rAddr, config, internalState.IsClient, internalState)
}

// ResumeWithOptions imports an already established dtls connection using a specific dtls state.
func ResumeWithOptions(state *State, conn net.PacketConn, rAddr net.Addr, opts ...Option) (*Conn, error) {
	config, err := buildConfig(opts...)
	if err != nil {
		return nil, err
	}

	return resumeWithConfig(state, conn, rAddr, config)
}
