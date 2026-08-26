// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package protocol provides the DTLS wire format
package protocol

// Version represents a DTLS protocol version.
type Version uint16

const (
	Version1_0 Version = 0xfeff
	Version1_2 Version = 0xfefd
	Version1_3 Version = 0xfefc
)

// Minor returns the minor version number.
func (v Version) Minor() uint8 {
	return uint8(v & 0xff)
}

// Major returns the major version number.
func (v Version) Major() uint8 {
	return uint8(v>>8) & 0xff
}

// VersionFromBytes constructs a Version from major/minor bytes.
func VersionFromBytes(major, minor uint8) Version {
	return Version(major)<<8 | Version(minor)
}
