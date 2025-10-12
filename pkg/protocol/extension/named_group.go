// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

// NamedGroup is a TLS 1.3 (and thus DTLS 1.3) named group code (RFC 8446 section 4.2.7).
type NamedGroup uint16

// Groups used by TLS 1.3 (RFC 8446 section 4.2.7).
const (
	// Elliptic Curve Groups (ECDHE).
	secp256R1 NamedGroup = 0x0017
	secp384r1 NamedGroup = 0x0018
	secp521r1 NamedGroup = 0x0019
	x25519    NamedGroup = 0x001D
	x448      NamedGroup = 0x001E

	// Finite Field Groups (DHE).
	ffdhe2048 NamedGroup = 0x0100
	ffdhe3072 NamedGroup = 0x0101
	ffdhe4096 NamedGroup = 0x0102
	ffdhe6144 NamedGroup = 0x0103
	ffdhe8192 NamedGroup = 0x0104
)

// Private-use ranges as defined in (RFC 8446 section 4.2.7).
const (
	// FFDHE private use: 0x01FC..0x01FF.
	FFDHEPrivateStart = 0x01FC
	FFDHEPrivateEnd   = 0x01FF

	// ECDHE private use: 0xFE00..0xFEFF.
	ECDHEPrivateStart = 0xFE00
	ECDHEPrivateEnd   = 0xFEFF
)

// IsValidNamedGroup returns if g is a known group or if it's within the
// RFC-designated private-use ranges. This is not a negotiation check.
func IsValidNamedGroup(group NamedGroup) bool {
	switch group {
	// ECDHE
	case secp256R1,
		secp384r1,
		secp521r1,
		x25519,
		x448:

		return true

	// FFDHE
	case ffdhe2048,
		ffdhe3072,
		ffdhe4096,
		ffdhe6144,
		ffdhe8192:

		return true
	}

	// check for private ranges.
	u := uint16(group)
	if (u >= FFDHEPrivateStart && u <= FFDHEPrivateEnd) ||
		(u >= ECDHEPrivateStart && u <= ECDHEPrivateEnd) {
		return true
	}

	return false
}
