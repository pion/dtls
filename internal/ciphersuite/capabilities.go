// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/protocol"
)

const (
	maxDTLS12PlaintextRecordLen = 1 << 14
	maxDTLS13InnerPlaintextLen  = maxDTLS12PlaintextRecordLen + 1
)

func mustAEADCapabilities(
	version protocol.Version,
	explicitNonceLen, tagLen, maskSampleLen int,
) cryptosuite.Capabilities {
	maxPlaintextLen := maxDTLS12PlaintextRecordLen
	if version == protocol.Version1_3 {
		maxPlaintextLen = maxDTLS13InnerPlaintextLen
	}
	capabilities, err := cryptosuite.NewAEADCapabilities(
		version,
		maxPlaintextLen,
		explicitNonceLen,
		tagLen,
		maskSampleLen,
	)
	if err != nil {
		return cryptosuite.Capabilities{}
	}

	return capabilities
}

func mustCBCCapabilities(macLen int) cryptosuite.Capabilities {
	const blockLen = 16

	capabilities, err := cryptosuite.NewCBCCapabilities(
		maxDTLS12PlaintextRecordLen,
		macLen,
		blockLen,
	)
	if err != nil {
		return cryptosuite.Capabilities{}
	}

	return capabilities
}
