// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !windows

package net

import (
	"errors"
	"io"
)

// IsShortBuffer reports whether a datagram exceeded the receive buffer.
func IsShortBuffer(err error) bool {
	return errors.Is(err, io.ErrShortBuffer)
}
