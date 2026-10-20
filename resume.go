// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"net"
)

// Resume imports an already established dtls connection using a specific dtls state.
// State restoration is unsafe unless the requirements documented on
// ResumeWithOptions are met.
//
// Deprecated: Use ResumeWithOptions instead.
func Resume(state *State, conn net.PacketConn, rAddr net.Addr, config *Config) (*Conn, error) {
	if config == nil {
		return nil, errNoConfigProvided
	}

	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if state == nil {
		return nil, errInvalidExportedState
	}
	serialized, err := state.export()
	if err != nil {
		return nil, err
	}
	state = &State{}
	state.deserialize(*serialized)
	if err := state.initCipherSuite(); err != nil {
		return nil, err
	}

	return createConn(conn, rAddr, config, state.isClient, state)
}

// ResumeWithOptions imports an already established dtls connection using a specific dtls state.
//
// Warning: v3 does not provide an atomic handoff from the original connection.
// Restoring state can reuse encryption keys and nonces, compromising
// confidentiality and integrity, unless the application ensures all of these:
//   - The original connection is quiescent before taking the snapshot and never
//     sends another record, including background retransmissions and alerts.
//   - No other connection uses the same exported keys and record counters.
//   - The state is restored at most once across all processes and copies.
//
// Calling Conn.Close after taking the snapshot is not a safe handoff: Close can
// send close_notify using a record counter that the restored connection reuses.
// Serialization alone neither stops the original connection nor enforces single
// use. Exported state contains secret key material and must be kept confidential
// and protected against modification.
//
// Prefer migrating to v4's Conn.ExportState and Resume APIs for an explicit
// handoff. Serialized state still requires application-enforced single use.
// If the application cannot guarantee these requirements on v3, establish a
// fresh connection instead. Or use ordinary session resumption.
func ResumeWithOptions(state *State, conn net.PacketConn, rAddr net.Addr, opts ...Option) (*Conn, error) {
	config, err := buildConfig(opts...)
	if err != nil {
		return nil, err
	}

	return Resume(state, conn, rAddr, config)
}
