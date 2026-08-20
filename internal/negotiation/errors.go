// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package negotiation

import (
	"errors"
	"fmt"

	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

var (
	errRetryMissingInitial         = errors.New("missing initial ClientHello or cipher suite")
	errRetryNoEffect               = errors.New("HelloRetryRequest has no effect")
	errRetryUnvalidatedRequest     = errors.New("unvalidated HelloRetryRequest")
	errRetryMissingFreshShare      = errors.New("missing fresh share for selected group")
	errRetryMissingSnapshot        = errors.New("missing ClientHello snapshot or retry request")
	errRetryChangedFields          = errors.New("ClientHello fields changed after HelloRetryRequest")
	errRetryWrongKeyShare          = errors.New("ClientHello2 did not contain exactly one requested key share")
	errRetryChangedExtensions      = errors.New("ClientHello extensions changed after HelloRetryRequest")
	errHelloVerifyMissingSnapshot  = errors.New("missing ClientHello snapshot")
	errHelloVerifyChangedFields    = errors.New("ClientHello fields changed after HelloVerifyRequest")
	errRetryFinalCipherSuite       = errors.New("final ServerHello changed the HelloRetryRequest cipher suite")
	errRetryCipherSuiteNotOffered  = errors.New("cipher suite was not offered")
	errRetryGroupNotOffered        = errors.New("selected group was not offered in supported_groups")
	errRetryGroupAlreadyShared     = errors.New("selected group already had a key share")
	errHelloVerifyExtensionChanged = errors.New("extension changed after HelloVerifyRequest")
)

func negotiationError(kind, err error, description alert.Description) error {
	return fmt.Errorf("%w: %w: %w", kind, err, &alert.Alert{Level: alert.Fatal, Description: description})
}
