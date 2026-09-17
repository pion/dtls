// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"math"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
)

// MarshalInnerPlaintext returns owned content || contentType || zero padding.
func MarshalInnerPlaintext(content []byte, contentType protocol.ContentType, padding int) ([]byte, error) {
	if contentType == 0 {
		return nil, dtlserrors.ErrInvalidContentType
	}
	if padding < 0 || len(content) >= math.MaxUint16 || padding > math.MaxUint16-len(content)-1 {
		return nil, ErrInvalidPacketLength
	}
	out := make([]byte, len(content)+1+padding)
	copy(out, content)
	out[len(content)] = byte(contentType)

	return out, nil
}

// ParseInnerPlaintext returns borrowed content.
func ParseInnerPlaintext(raw []byte) (content []byte, contentType protocol.ContentType, padding int, err error) {
	for i := len(raw) - 1; i >= 0; i-- {
		if raw[i] != 0 {
			return raw[:i], protocol.ContentType(raw[i]), len(raw) - i - 1, nil
		}
	}

	return nil, 0, 0, dtlserrors.ErrBufferTooSmall
}
