// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func FuzzHeaderCIDUnmarshal(f *testing.F) {
	const cidLength = 4

	for _, header := range []Header{
		{ContentType: protocol.ContentTypeApplicationData, ContentLen: 3, Version: protocol.Version1_2, Epoch: 1, SequenceNumber: 2},
		{ContentType: protocol.ContentTypeConnectionID, ContentLen: 3, Version: protocol.Version1_2, Epoch: 1, SequenceNumber: 2, ConnectionID: []byte{0x01, 0x02, 0x03, 0x04}},
	} {
		raw, err := header.Marshal()
		if err != nil {
			f.Fatalf("marshal fuzz seed: %v", err)
		}
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		header := Header{ConnectionID: make([]byte, cidLength)}
		if err := header.Unmarshal(data); err != nil {
			return
		}

		raw, err := header.Marshal()
		require.NoError(t, err)
		require.Equal(t, data[:header.MarshalSize()], raw)
	})
}
