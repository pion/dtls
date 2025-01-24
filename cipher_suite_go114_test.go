// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build go1.14
// +build go1.14

package dtls

import (
	"testing"
)

func TestInsecureCipherSuites(t *testing.T) {
	r := InsecureCipherSuites()

	if len(r) != 0 {
		t.Fatalf("Expected no insecure ciphersuites, got %d", len(r))
	}
}

func TestCipherSuites(t *testing.T) {
	ours := allCipherSuites()
	theirs := CipherSuites()

	if len(ours) != len(theirs) {
		t.Fatalf("Expected %d CipherSuites, got %d", len(ours), len(theirs))
	}

	for i, s := range ours {
		i := i
		s := s
		t.Run(s.String(), func(t *testing.T) {
			cipher := theirs[i]
			if cipher.ID != uint16(s.ID()) {
				t.Fatalf("Expected ID: 0x%04X, got 0x%04X", s.ID(), cipher.ID)
			}

			if cipher.Name != s.String() {
				t.Fatalf("Expected Name: %s, got %s", s.String(), cipher.Name)
			}

			if len(cipher.SupportedVersions) != 1 {
				t.Fatalf("Expected %d SupportedVersion, got %d", 1, len(cipher.SupportedVersions))
			}

			if cipher.SupportedVersions[0] != VersionDTLS12 {
				t.Fatalf("Expected SupportedVersions 0x%04X, got 0x%04X", VersionDTLS12, cipher.SupportedVersions[0])
			}

			if cipher.Insecure {
				t.Fatalf("Expected Insecure %t, got %t", false, cipher.Insecure)
			}
		})
	}
}
