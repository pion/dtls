// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"slices"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

// ALPNProtocolSelection negotiates a shared protocol according to #3.2 of rfc7301.
func ALPNProtocolSelection(supportedProtocols, peerSupportedProtocols []string) (string, error) {
	if len(supportedProtocols) == 0 || len(peerSupportedProtocols) == 0 {
		return "", nil
	}
	for _, s := range supportedProtocols {
		if slices.Contains(peerSupportedProtocols, s) {
			return s, nil
		}
	}

	return "", dtlserrors.ErrALPNNoAppProto
}
