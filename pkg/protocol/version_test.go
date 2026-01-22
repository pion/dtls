// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package protocol provides the DTLS wire format
package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b Version
		want bool
	}{
		{"same-1.0", Version1_0, Version1_0, true},
		{"same-1.2", Version1_2, Version1_2, true},
		{"same-1.3", Version1_3, Version1_3, true},
		{"diff-major", Version{Major: 0xfe, Minor: 0xfd}, Version{Major: 0xff, Minor: 0xfd}, false},
		{"diff-minor", Version{Major: 0xfe, Minor: 0xfd}, Version{Major: 0xfe, Minor: 0xfc}, false},
		{"completely-diff", Version{Major: 0x03, Minor: 0x03}, Version{Major: 0xfe, Minor: 0xff}, false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := tc.a.Equal(tc.b)
			assert.Equal(t, tc.want, got, "Equal(%v,%v)", tc.a, tc.b)
		})
	}
}

func TestIsSupportedBytes(t *testing.T) {
	cases := []struct {
		maj, min uint8
		want     bool
	}{
		{0xfe, 0xfd, true},  // DTLS 1.2
		{0xfe, 0xfc, true},  // DTLS 1.3 (work in progress)
		{0xfe, 0xff, false}, // DTLS 1.0 not supported
		{0x03, 0x03, false}, // TLS 1.2, not DTLS
		{0x00, 0x00, false},
	}

	for _, c := range cases {
		got := IsSupportedBytes(c.maj, c.min)
		assert.Equalf(t, c.want, got, "IsSupportedBytes(%#02x,%#02x)", c.maj, c.min)
	}
}

func TestIsSupportedVersion(t *testing.T) {
	cases := []struct {
		v    Version
		want bool
	}{
		{Version1_2, true},
		{Version1_3, true},                         // WIP, supported
		{Version1_0, false},                        // not supported
		{Version{Major: 0x03, Minor: 0x03}, false}, // TLS 1.2, not DTLS
	}

	for _, c := range cases {
		got := IsSupportedVersion(c.v)
		assert.Equal(t, c.want, got, "IsSupportedVersion(%v)", c.v)
	}
}

func TestIsValidBytes(t *testing.T) {
	// Valid DTLS codes per RFC 9147 §5.3: feff (1.0), fefd (1.2), fefc (1.3)
	cases := []struct {
		maj, min uint8
		want     bool
	}{
		{0xfe, 0xff, true},  // DTLS 1.0 (valid, though not supported)
		{0xfe, 0xfd, true},  // DTLS 1.2
		{0xfe, 0xfc, true},  // DTLS 1.3
		{0xfe, 0x00, false}, // invalid
		{0x03, 0x03, false}, // TLS 1.2, invalid
	}

	for _, c := range cases {
		got := IsValidBytes(c.maj, c.min)
		assert.Equalf(t, c.want, got, "IsValidBytes(%#02x,%#02x)", c.maj, c.min)
	}
}

func TestIsValidVersion(t *testing.T) {
	cases := []struct {
		v    Version
		want bool
	}{
		{Version1_0, true},
		{Version1_2, true},
		{Version1_3, true},
		{Version{Major: 0xfe, Minor: 0x00}, false}, // invalid
		{Version{Major: 0x03, Minor: 0x03}, false}, // TLS 1.2
	}

	for _, c := range cases {
		got := IsValidVersion(c.v)
		assert.Equal(t, c.want, got, "IsValidVersion(%v)", c.v)
	}
}
