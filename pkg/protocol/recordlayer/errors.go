// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package recordlayer provides lossless DTLS datagram framing for
// [DTLS 1.2](https://www.rfc-editor.org/rfc/rfc6347#section-4.1) and
// [DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147#section-4), along with the
// wire header values required by record protection implementations.
package recordlayer

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

// ErrInvalidPacketLength is returned when the packet length too small
// or declared length do not match.
var ErrInvalidPacketLength = dtlserrors.ErrInvalidPacketLength
