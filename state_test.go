// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"encoding/gob"
	"testing"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestGenerateStateRejectsDTLS13(t *testing.T) {
	internalState := &dtlsstate.State{
		Common: &dtlsstate.Common{
			LocalVersion: protocol.Version1_3,
			CipherSuite:  ciphersuite.ForID(ciphersuite.TLS_AES_128_GCM_SHA256, nil),
		},
	}

	_, err := generateState(internalState)
	require.ErrorIs(t, err, ErrStateSerializationUnsupported)
}

func TestUnmarshalBinaryRejectsDTLS13State(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, gob.NewEncoder(&buf).Encode(serializedState{
		Version:       protocol.Version1_3,
		CipherSuiteID: uint16(ciphersuite.TLS_AES_128_GCM_SHA256),
	}))

	var state State
	err := state.UnmarshalBinary(buf.Bytes())
	require.ErrorIs(t, err, ErrStateSerializationUnsupported)
}
