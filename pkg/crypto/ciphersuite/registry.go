// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import "crypto/tls"

// ID is a registered TLS cipher-suite identifier.
type ID uint16

// Supported cipher-suite identifiers.
const (
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM              ID = 0xc0ac // nolint: revive,staticcheck
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8            ID = 0xc0ae // nolint: revive,staticcheck
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       ID = 0xc02b // nolint: revive,staticcheck
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         ID = 0xc02f // nolint: revive,staticcheck
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       ID = 0xc02c // nolint: revive,staticcheck
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         ID = 0xc030 // nolint: revive,staticcheck
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          ID = 0xc00a // nolint: revive,staticcheck
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            ID = 0xc014 // nolint: revive,staticcheck
	TLS_PSK_WITH_AES_128_CCM                      ID = 0xc0a4 // nolint: revive,staticcheck
	TLS_PSK_WITH_AES_128_CCM_8                    ID = 0xc0a8 // nolint: revive,staticcheck
	TLS_PSK_WITH_AES_256_CCM_8                    ID = 0xc0a9 // nolint: revive,staticcheck
	TLS_PSK_WITH_AES_128_GCM_SHA256               ID = 0x00a8 // nolint: revive,staticcheck
	TLS_PSK_WITH_AES_128_CBC_SHA256               ID = 0x00ae // nolint: revive,staticcheck
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256         ID = 0xc037 // nolint: revive,staticcheck
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ID = 0xcca9 // nolint: revive,staticcheck
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   ID = 0xcca8 // nolint: revive,staticcheck
	TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         ID = 0xccab // nolint: revive,staticcheck
	TLS_AES_128_GCM_SHA256                        ID = 0x1301 // nolint: revive,staticcheck
	TLS_AES_256_GCM_SHA384                        ID = 0x1302 // nolint: revive,staticcheck
	TLS_CHACHA20_POLY1305_SHA256                  ID = 0x1303 // nolint: revive,staticcheck
)

func (i ID) String() string { //nolint:cyclop
	switch i { //nolint:exhaustive
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"
	case TLS_PSK_WITH_AES_128_CCM:
		return "TLS_PSK_WITH_AES_128_CCM"
	case TLS_PSK_WITH_AES_128_CCM_8:
		return "TLS_PSK_WITH_AES_128_CCM_8"
	case TLS_PSK_WITH_AES_256_CCM_8:
		return "TLS_PSK_WITH_AES_256_CCM_8"
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return "TLS_PSK_WITH_AES_128_GCM_SHA256"
	case TLS_PSK_WITH_AES_128_CBC_SHA256:
		return "TLS_PSK_WITH_AES_128_CBC_SHA256"
	case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"
	case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"
	}

	return tls.CipherSuiteName(uint16(i))
}
