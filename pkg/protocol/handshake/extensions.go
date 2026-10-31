// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"

	"github.com/pion/dtls/v4/internal/handshakewire"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
)

func serverHelloExtensionContext(random Random, rawExtensions []extension.Raw) handshakewire.Context {
	randomBytes := random.MarshalFixed()
	if bytes.Equal(randomBytes[:], HelloRetryRequestRandom()) {
		return handshakewire.ContextHelloRetryRequest
	}

	for _, raw := range rawExtensions {
		//nolint:exhaustive // Only extensions unique to DTLS 1.3 identify this context.
		switch raw.Type {
		case extension.TypeSupportedVersions, extension.TypeKeyShare, extension.TypePreSharedKey:
			return handshakewire.ContextServerHello13
		}
	}

	return handshakewire.ContextServerHello12
}
