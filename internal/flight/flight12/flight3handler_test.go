// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"testing"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlight3GenerateReusesHookOnlyConnectionIDAfterVersionDowngrade(t *testing.T) {
	for name, cid := range map[string][]byte{
		"Empty":    {},
		"NonEmpty": {0xcc},
	} {
		t.Run(name, func(t *testing.T) {
			state13 := dtlsstate.NewState13(true)
			state13.SetLocalConnectionID(cid)
			state13.LocalCIDOffered = true
			state := dtlsstate.Activate12(&state13)
			cfg := &dtlsconfig.HandshakeConfig{
				ClientHelloMessageHook: func(clientHello handshake.MessageClientHello) handshake.Message {
					clientHello.Extensions = append(clientHello.Extensions, &extension.ConnectionID{CID: cid})

					return &clientHello
				},
			}

			packets, dtlsAlert, err := generateForTest(t, Flight3, nil, state, nil, cfg)
			require.NoError(t, err)
			require.Nil(t, dtlsAlert)
			require.Len(t, packets, 1)
			hand, ok := packets[0].Record.Content.(*handshake.Handshake)
			require.True(t, ok)
			clientHello, ok := hand.Message.(*handshake.MessageClientHello)
			require.True(t, ok)

			connectionIDs := make([][]byte, 0, 1)
			for _, ext := range clientHello.Extensions {
				if connectionID, ok := ext.(*extension.ConnectionID); ok {
					connectionIDs = append(connectionIDs, connectionID.CID)
				}
			}
			require.Len(t, connectionIDs, 1)
			assert.Equal(t, cid, connectionIDs[0])
		})
	}
}
