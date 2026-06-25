// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package recordlayer implements the TLS Record Layer https://tools.ietf.org/html/rfc5246#section-6
package recordlayer

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

// ErrInvalidPacketLength is returned when the packet length too small
// or declared length do not match.
var ErrInvalidPacketLength = dtlserrors.ErrInvalidPacketLength //nolint:gochecknoglobals
