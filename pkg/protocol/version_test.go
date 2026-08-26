// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package protocol provides the DTLS wire format
package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionMinorMajor(t *testing.T) {
	assert.Equal(t, uint8(0xff), Version1_0.Minor())
	assert.Equal(t, uint8(0xfe), Version1_0.Major())
	assert.Equal(t, uint8(0xfd), Version1_2.Minor())
	assert.Equal(t, uint8(0xfe), Version1_2.Major())
	assert.Equal(t, uint8(0xfc), Version1_3.Minor())
	assert.Equal(t, uint8(0xfe), Version1_3.Major())
}

func TestVersionFromBytes(t *testing.T) {
	assert.Equal(t, Version1_0, VersionFromBytes(0xfe, 0xff))
	assert.Equal(t, Version1_2, VersionFromBytes(0xfe, 0xfd))
	assert.Equal(t, Version1_3, VersionFromBytes(0xfe, 0xfc))
}
