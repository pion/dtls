// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
)

// ErrInvalidPacketLength is returned when the packet length too small
// or declared length do not match.
var ErrInvalidPacketLength = dtlserrors.ErrInvalidPacketLength
