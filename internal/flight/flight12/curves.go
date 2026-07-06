// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"slices"

	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
)

func supportedEllipticCurves(curves []elliptic.Curve) []elliptic.Curve {
	if !slices.Contains(curves, elliptic.X25519MLKEM768) {
		return curves
	}

	filtered := make([]elliptic.Curve, 0, len(curves))
	for _, curve := range curves {
		if curve != elliptic.X25519MLKEM768 {
			filtered = append(filtered, curve)
		}
	}

	return filtered
}

func selectEllipticCurve(localCurves, remoteCurves []elliptic.Curve) (elliptic.Curve, bool) {
	localCurves = supportedEllipticCurves(localCurves)
	for _, remoteCurve := range remoteCurves {
		if slices.Contains(localCurves, remoteCurve) {
			return remoteCurve, true
		}
	}

	return 0, false
}
