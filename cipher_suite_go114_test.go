// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build go1.14
// +build go1.14

package dtls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInsecureCipherSuites(t *testing.T) {
	assert.Empty(t, InsecureCipherSuites(), "Expected no insecure ciphersuites")
}

func TestCipherSuites(t *testing.T) {
	ours := allCipherSuites()
	theirs := CipherSuites()
	assert.Equal(t, len(ours), len(theirs))

	for i, s := range ours {
		i := i
		s := s
		t.Run(s.String(), func(t *testing.T) {
			cipher := theirs[i]
			assert.Equal(t, cipher.ID, uint16(s.ID()))
			assert.Equal(t, cipher.Name, s.String())
			assert.Equal(t, 1, len(cipher.SupportedVersions), "Expected SupportedVersion to be 1")
			assert.Equal(t, uint16(VersionDTLS12), cipher.SupportedVersions[0], "Expected SupportedVersion to match")
			assert.False(t, cipher.Insecure, "Expected Insecure")
		})
	}
}
