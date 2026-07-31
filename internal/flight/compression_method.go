// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight

import "github.com/pion/dtls/v3/pkg/protocol"

// DefaultCompressionMethods returns the supported compression methods.
func DefaultCompressionMethods() []*protocol.CompressionMethod {
	return []*protocol.CompressionMethod{
		{},
	}
}
