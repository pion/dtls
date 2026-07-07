// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
)

// Active is a concrete DTLS version state that shares common connection fields.
type Active interface {
	CommonFields() *Common
}

// NewActive creates a DTLS 1.2 active state with initialized common fields.
func NewActive(isClient bool) Active {
	return &State12{
		Common: &Common{
			IsClient: isClient,
		},
	}
}

// CommonState returns the common state shared by an active DTLS version state.
func CommonState(active Active) *Common {
	if active == nil {
		return &Common{}
	}
	if common := active.CommonFields(); common != nil {
		return common
	}

	common := &Common{}
	switch state := active.(type) {
	case *State12:
		state.Common = common
	case *State13:
		state.Common = common
	}

	return common
}

// Activate12 returns a DTLS 1.2 active state, preserving common fields and
// handshake sequence counters.
func Activate12(active Active) *State12 {
	common := CommonState(active)
	if state, ok := active.(*State12); ok {
		state.Common = common

		return state
	}

	state := &State12{Common: common}
	if state13, ok := active.(*State13); ok {
		state.HandshakeSendSequence = state13.HandshakeSendSequence
		state.HandshakeRecvSequence = state13.HandshakeRecvSequence
	}

	return state
}

// Activate13 returns a DTLS 1.3 active state, preserving common fields and
// handshake sequence counters.
func Activate13(active Active) *State13 {
	common := CommonState(active)
	if state, ok := active.(*State13); ok {
		state.Common = common
		if state.LocalKeypairs == nil {
			state.LocalKeypairs = make(map[elliptic.Curve]*elliptic.Keypair)
		}

		return state
	}

	state := &State13{
		Common:        common,
		LocalKeypairs: make(map[elliptic.Curve]*elliptic.Keypair),
	}
	if state12, ok := active.(*State12); ok {
		state.HandshakeSendSequence = state12.HandshakeSendSequence
		state.HandshakeRecvSequence = state12.HandshakeRecvSequence
	}

	return state
}

func As12(active Active) (*State12, error) {
	state, ok := active.(*State12)
	if !ok {
		return nil, dtlserrors.ErrInvalidProtocolVersionState
	}

	return state, nil
}

func As13(active Active) (*State13, error) {
	state, ok := active.(*State13)
	if !ok {
		return nil, dtlserrors.ErrInvalidProtocolVersionState
	}

	return state, nil
}

func HandshakeRecvSequence(active Active) int {
	switch state := active.(type) {
	case *State13:
		return state.HandshakeRecvSequence
	case *State12:
		return state.HandshakeRecvSequence
	default:
		return 0
	}
}

func NextHandshakeSendSequence(active Active) uint16 {
	switch state := active.(type) {
	case *State13:
		seq := state.HandshakeSendSequence
		state.HandshakeSendSequence++

		return uint16(seq) //nolint:gosec // G115
	case *State12:
		seq := state.HandshakeSendSequence
		state.HandshakeSendSequence++

		return uint16(seq) //nolint:gosec // G115
	default:
		return 0
	}
}
