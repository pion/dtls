// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

func decodeCipherSuiteIDs(buf []byte) ([]uint16, error) {
	if len(buf) < 2 {
		return nil, dtlserrors.ErrBufferTooSmall
	}
	cipherSuitesCount := int(binary.BigEndian.Uint16(buf[0:])) / 2
	ids := make([]uint16, cipherSuitesCount)
	for i := range cipherSuitesCount {
		if len(buf) < (i*2 + 4) {
			return nil, dtlserrors.ErrBufferTooSmall
		}

		ids[i] = binary.BigEndian.Uint16(buf[(i*2)+2:])
	}

	return ids, nil
}
