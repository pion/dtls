// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package config

import "github.com/pion/dtls/v3/pkg/protocol"

// NormalizeProtocolVersionRange constrains the version range to supported DTLS versions.
func NormalizeProtocolVersionRange(
	minVersion, maxVersion protocol.Version,
) (protocol.Version, protocol.Version) {
	if !minVersion.Equal(protocol.Version1_3) {
		minVersion = protocol.Version1_2
	}

	if !maxVersion.Equal(protocol.Version1_3) {
		maxVersion = protocol.Version1_2
	}

	return minVersion, maxVersion
}

// SupportedVersionsRange returns the supported DTLS versions from maxVersion
// down to minVersion, in preference order (newest first). Only DTLS 1.2 and
// 1.3 are emitted.
func SupportedVersionsRange(minVersion, maxVersion protocol.Version) []protocol.Version {
	ordered := []protocol.Version{protocol.Version1_3, protocol.Version1_2}
	out := make([]protocol.Version, 0, len(ordered))
	for _, version := range ordered {
		if versionAtLeast(version, minVersion) && versionAtMost(version, maxVersion) {
			out = append(out, version)
		}
	}

	return out
}

// SelectVersion picks the highest-preference version from remote that is
// within the local [minVersion, maxVersion] range.
func SelectVersion(
	remote []protocol.Version,
	minVersion, maxVersion protocol.Version,
) (protocol.Version, bool) {
	for _, version := range remote {
		if versionAtLeast(version, minVersion) && versionAtMost(version, maxVersion) {
			return version, true
		}
	}

	return protocol.Version{}, false
}

func versionAtLeast(version, minVersion protocol.Version) bool {
	// DTLS encodes newer versions as numerically smaller Minor bytes.
	return version.Minor <= minVersion.Minor
}

func versionAtMost(version, maxVersion protocol.Version) bool {
	return version.Minor >= maxVersion.Minor
}
