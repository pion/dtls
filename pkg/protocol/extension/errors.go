// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

// ErrALPNInvalidFormat is raised when the ALPN format is invalid.
var ErrALPNInvalidFormat = dtlserrors.ErrALPNInvalidFormat //nolint:gochecknoglobals
