// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"slices"

	"github.com/pion/dtls/v3/pkg/protocol"
)

func normalizeProtocolVersionRange(minVersion, maxVersion protocol.Version) (protocol.Version, protocol.Version) {
	if !minVersion.Equal(protocol.Version1_3) {
		minVersion = protocol.Version1_2
	}

	if !maxVersion.Equal(protocol.Version1_3) {
		maxVersion = protocol.Version1_2
	}

	return minVersion, maxVersion
}

// supportedVersionsRange returns the supported DTLS versions from maxVersion
// down to minVersion, in preference order (newest first). Only DTLS 1.2 and
// 1.3 are emitted.
func supportedVersionsRange(minVersion, maxVersion protocol.Version) []protocol.Version {
	ordered := []protocol.Version{protocol.Version1_3, protocol.Version1_2}
	out := make([]protocol.Version, 0, len(ordered))
	for _, v := range ordered {
		if versionAtLeast(v, minVersion) && versionAtMost(v, maxVersion) {
			out = append(out, v)
		}
	}

	return out
}

// selectVersion picks the highest-preference version from remote that is
// within the local [minVersion, maxVersion] range. Returns false if there
// is no intersection.
func selectVersion(
	remote []protocol.Version,
	minVersion, maxVersion protocol.Version,
) (protocol.Version, bool) {
	for _, v := range remote {
		if versionAtLeast(v, minVersion) && versionAtMost(v, maxVersion) {
			return v, true
		}
	}

	return protocol.Version{}, false
}

func versionAtLeast(v, lo protocol.Version) bool {
	// DTLS encodes newer versions as numerically smaller Minor bytes
	return v.Minor <= lo.Minor
}

func versionAtMost(v, hi protocol.Version) bool {
	return v.Minor >= hi.Minor
}

func findMatchingSRTPProfile(a, b []SRTPProtectionProfile) (SRTPProtectionProfile, bool) {
	for _, aProfile := range a {
		if slices.Contains(b, aProfile) {
			return aProfile, true
		}
	}

	return 0, false
}

func findMatchingCipherSuite(a, b []CipherSuite) (CipherSuite, bool) {
	for _, aSuite := range a {
		for _, bSuite := range b {
			if aSuite.ID() == bSuite.ID() {
				return aSuite, true
			}
		}
	}

	return nil, false
}

func splitBytes(bytes []byte, splitLen int) [][]byte {
	splitBytes := make([][]byte, 0)
	numBytes := len(bytes)
	for i := 0; i < numBytes; i += splitLen {
		j := min(i+splitLen, numBytes)

		splitBytes = append(splitBytes, bytes[i:j])
	}

	return splitBytes
}
