// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Records queued for a later epoch must not share memory with the pooled
// read buffer, which the next readAndBuffer call reuses.
func TestEnqueueEncryptedPacketsCopiesData(t *testing.T) {
	conn := &Conn{}
	buf := []byte{0x17, 0xfe, 0xfd, 0x00, 0x01}
	assert.True(t, conn.enqueueEncryptedPackets(addrPkt{data: buf}))

	copy(buf, []byte{0xff, 0xff, 0xff, 0xff, 0xff}) // the pool hands the buffer to the next read

	assert.Equal(t, []byte{0x17, 0xfe, 0xfd, 0x00, 0x01}, conn.encryptedPackets[0].data)
}
