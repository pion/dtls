// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight

import (
	"slices"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	"github.com/pion/dtls/v3/pkg/protocol"
)

func DefaultCompressionMethods() []*protocol.CompressionMethod {
	return []*protocol.CompressionMethod{
		{},
	}
}

func FindMatchingSRTPProfile(a, b []dtlsconfig.SRTPProtectionProfile) (dtlsconfig.SRTPProtectionProfile, bool) {
	for _, p1 := range a {
		if slices.Contains(b, p1) {
			return p1, true
		}
	}

	return 0, false
}

func FindMatchingCipherSuite(a, b []dtlsconfig.CipherSuite) (dtlsconfig.CipherSuite, bool) {
	for _, p1 := range a {
		for _, p2 := range b {
			if p1.ID() == p2.ID() {
				return p1, true
			}
		}
	}

	return nil, false
}

func CipherSuiteIDs(cipherSuites []dtlsconfig.CipherSuite) []uint16 {
	rtrn := []uint16{}
	for _, c := range cipherSuites {
		rtrn = append(rtrn, uint16(c.ID()))
	}

	return rtrn
}
