// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package negotiation

import (
	"bytes"
	"fmt"
	"slices"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// RetryRequest is the set of changes authorized by one validated
// HelloRetryRequest.
type RetryRequest struct {
	CipherSuiteID    uint16
	SelectedGroup    elliptic.Curve
	Cookie           []byte
	HasSelectedGroup bool
	HasCookie        bool
	valid            bool
}

// ValidateHelloRetryRequest validates the parts of an HRR that constrain
// ClientHello2 and the final ServerHello.
//
// https://www.rfc-editor.org/rfc/rfc9846#section-4.2.4
func ValidateHelloRetryRequest(
	initial ClientHelloSnapshot,
	hrr *handshake.MessageServerHello,
) (RetryRequest, error) {
	if !initial.Valid() || hrr == nil || hrr.CipherSuiteID == nil {
		return RetryRequest{}, negotiationError(
			dtlserrors.ErrInvalidHelloRetryRequest,
			errRetryMissingInitial,
			alert.IllegalParameter,
		)
	}

	initialHello, err := ClientHelloFromSnapshot(initial)
	if err != nil {
		return RetryRequest{}, negotiationError(
			dtlserrors.ErrInvalidHelloRetryRequest,
			err,
			alert.IllegalParameter,
		)
	}
	if !slices.Contains(initialHello.CipherSuiteIDs, *hrr.CipherSuiteID) {
		return RetryRequest{}, negotiationError(
			dtlserrors.ErrInvalidHelloRetryRequest,
			fmt.Errorf("%w: %d", errRetryCipherSuiteNotOffered, *hrr.CipherSuiteID),
			alert.IllegalParameter,
		)
	}
	request := retryRequest(*hrr.CipherSuiteID, hrr.Extensions())
	if err = validateRetrySelectedGroup(initialHello, request); err != nil {
		return RetryRequest{}, err
	}
	changed, err := helloRetryRequestChangesClientHello(initial, request)
	if err != nil {
		return RetryRequest{}, err
	}
	if !changed {
		return RetryRequest{}, negotiationError(
			dtlserrors.ErrInvalidHelloRetryRequest, errRetryNoEffect, alert.IllegalParameter,
		)
	}

	request.valid = true

	return request, nil
}

// BuildClientHelloRetry clones the exact finalized ClientHello1 and applies
// only the changes authorized by request. The caller may run its hook on the
// result, but must validate the hook result with ValidateClientHelloRetry.
//
// https://www.rfc-editor.org/rfc/rfc9846#section-4.2.2
// https://www.rfc-editor.org/rfc/rfc9846#section-4.2.4
func BuildClientHelloRetry(
	initial ClientHelloSnapshot,
	request RetryRequest,
	freshShare *extension13.KeyShareEntry,
) (*handshake.MessageClientHello, error) {
	if !request.valid {
		return nil, negotiationError(dtlserrors.ErrInvalidClientHello, errRetryUnvalidatedRequest, alert.IllegalParameter)
	}
	if request.HasSelectedGroup &&
		(freshShare == nil || freshShare.Group != request.SelectedGroup || len(freshShare.KeyExchange) == 0) {
		return nil, negotiationError(dtlserrors.ErrInvalidClientHello, errRetryMissingFreshShare, alert.IllegalParameter)
	}

	clientHello, err := ClientHelloFromSnapshot(initial)
	if err != nil {
		return nil, negotiationError(dtlserrors.ErrInvalidClientHello, err, alert.IllegalParameter)
	}

	clientHello.SetExtensions(buildRetryExtensions(clientHello.Extensions(), request, freshShare))

	return clientHello, nil
}

// ValidateClientHelloRetry requires ClientHello2 to equal ClientHello1
// except for the changes authorized by a validated HelloRetryRequest, removal
// of early_data, and padding changes.
//
// https://www.rfc-editor.org/rfc/rfc9846#section-4.2.2
func ValidateClientHelloRetry(
	initial, retry ClientHelloSnapshot,
	request RetryRequest,
) error {
	if !initial.Valid() || !retry.Valid() || !request.valid {
		return negotiationError(
			dtlserrors.ErrInvalidClientHello, errRetryMissingSnapshot,
			alert.IllegalParameter,
		)
	}

	return validateRetryClientHello(initial, retry, request)
}

// ValidateHelloVerifyRequestResponse validates the RFC 6347 fields that must remain
// stable across HelloVerifyRequest. DTLS 1.2 does
// not require byte-for-byte extension equality, but the existing CID and SRTP
// retry validation still apply.
func ValidateHelloVerifyRequestResponse(initial, retry ClientHelloSnapshot, cookie []byte) error {
	if !initial.Valid() || !retry.Valid() {
		return negotiationError(dtlserrors.ErrInvalidClientHello, errHelloVerifyMissingSnapshot, alert.IllegalParameter)
	}
	firstBeforeCookie, firstAfterCookie, _ := helloVerifyClientHelloParts(initial)
	secondBeforeCookie, secondAfterCookie, secondCookie := helloVerifyClientHelloParts(retry)
	if !bytes.Equal(firstBeforeCookie, secondBeforeCookie) || !bytes.Equal(firstAfterCookie, secondAfterCookie) {
		return negotiationError(dtlserrors.ErrInvalidClientHello, errHelloVerifyChangedFields, alert.IllegalParameter)
	}
	if !bytes.Equal(secondCookie, cookie) {
		return negotiationError(
			dtlserrors.ErrInvalidClientHello,
			fmt.Errorf("ClientHello did not echo the latest cookie: %w", dtlserrors.ErrCookieMismatch),
			alert.IllegalParameter,
		)
	}
	if err := validateHelloVerifyExtension(initial, retry, extension.TypeConnectionID); err != nil {
		return err
	}
	if err := ValidateSRTPRetry(initial, retry); err != nil {
		return err
	}

	return nil
}

// ValidateServerHelloAfterRetry binds the final ServerHello to the cipher
// suite and selected group from the preceding HelloRetryRequest.
func ValidateServerHelloAfterRetry(request RetryRequest, serverHello *handshake.MessageServerHello) error {
	if !request.valid {
		return negotiationError(dtlserrors.ErrInvalidServerHello, errRetryUnvalidatedRequest, alert.IllegalParameter)
	}
	if serverHello == nil || serverHello.CipherSuiteID == nil || *serverHello.CipherSuiteID != request.CipherSuiteID {
		return negotiationError(dtlserrors.ErrInvalidServerHello, errRetryFinalCipherSuite, alert.IllegalParameter)
	}
	if request.HasSelectedGroup {
		var share *extension13.ServerKeyShare
		for _, value := range serverHello.Extensions() {
			if candidate, ok := value.(*extension13.ServerKeyShare); ok {
				share = candidate

				break
			}
		}
		if share == nil {
			return negotiationError(
				dtlserrors.ErrInvalidServerHello, dtlserrors.ErrServerKeyShareMissing, alert.IllegalParameter,
			)
		}
		if share.Share.Group != request.SelectedGroup {
			return negotiationError(
				dtlserrors.ErrInvalidServerHello, dtlserrors.ErrServerKeyShareUnknownGroup, alert.IllegalParameter,
			)
		}
	}

	return nil
}

// ClientHelloFromSnapshot returns a detached decoded copy of snapshot.
func ClientHelloFromSnapshot(snapshot ClientHelloSnapshot) (*handshake.MessageClientHello, error) {
	if !snapshot.Valid() {
		return nil, dtlserrors.ErrInvalidClientHello
	}
	clientHello := &handshake.MessageClientHello{}
	if err := clientHello.Unmarshal(snapshot.body); err != nil {
		return nil, fmt.Errorf("snapshot ClientHello: %w", err)
	}

	return clientHello, nil
}

// RFC 9846 Section 4.2.4 permits HRR to request one group and / or a cookie.
//
// https://www.rfc-editor.org/rfc/rfc9846#section-4.2.4
func retryRequest(cipherSuiteID uint16, values []extension.Value) RetryRequest {
	request := RetryRequest{CipherSuiteID: cipherSuiteID}
	for _, value := range values {
		if selectedGroup, ok := value.(*extension13.RetryKeyShare); ok {
			request.SelectedGroup = selectedGroup.SelectedGroup
			request.HasSelectedGroup = true
		}
		if cookie, ok := value.(*extension13.Cookie); ok {
			request.Cookie = bytes.Clone(cookie.Cookie)
			request.HasCookie = true
		}
	}

	return request
}

func validateRetrySelectedGroup(initial *handshake.MessageClientHello, request RetryRequest) error {
	if !request.HasSelectedGroup {
		return nil
	}
	var groups []elliptic.Curve
	var shares []extension13.KeyShareEntry
	for _, value := range initial.Extensions() {
		if supported, ok := value.(*extension.SupportedGroups); ok {
			groups = supported.Groups
		}
		if keyShare, ok := value.(*extension13.ClientKeyShare); ok {
			shares = keyShare.Shares
		}
	}
	if !slices.Contains(groups, request.SelectedGroup) {
		return negotiationError(
			dtlserrors.ErrInvalidHelloRetryRequest,
			fmt.Errorf("%w: %d", errRetryGroupNotOffered, request.SelectedGroup),
			alert.IllegalParameter,
		)
	}
	if slices.ContainsFunc(shares, func(share extension13.KeyShareEntry) bool {
		return share.Group == request.SelectedGroup
	}) {
		return negotiationError(
			dtlserrors.ErrInvalidHelloRetryRequest,
			fmt.Errorf("%w: %d", errRetryGroupAlreadyShared, request.SelectedGroup),
			alert.IllegalParameter,
		)
	}

	return nil
}

func helloRetryRequestChangesClientHello(initial ClientHelloSnapshot, request RetryRequest) (bool, error) {
	if request.HasSelectedGroup {
		return true, nil
	}
	if !request.HasCookie {
		return false, nil
	}
	payload, err := (extension13.Cookie{Cookie: request.Cookie}).MarshalData()
	if err != nil {
		return false, negotiationError(dtlserrors.ErrInvalidHelloRetryRequest, err, alert.IllegalParameter)
	}
	initialCookie, present := initial.Extension(extension.TypeCookie)

	return !present || !bytes.Equal(initialCookie.Data, payload), nil
}

func buildRetryExtensions(
	initial []extension.Value,
	request RetryRequest,
	freshShare *extension13.KeyShareEntry,
) []extension.Value {
	result := make([]extension.Value, 0, len(initial)+2)
	keyShareApplied, cookieApplied := false, false
	for _, value := range initial {
		replacement, replace, discard := retryExtensionReplacement(value, request, freshShare)
		if discard {
			continue
		}
		if replace {
			result = append(result, replacement)
			if replacement.ExtensionType() == extension.TypeKeyShare {
				keyShareApplied = true
			} else {
				cookieApplied = true
			}

			continue
		}
		result = append(result, value)
	}

	return insertMissingRetryExtensions(result, request, freshShare, keyShareApplied, cookieApplied)
}

func retryExtensionReplacement(
	value extension.Value,
	request RetryRequest,
	freshShare *extension13.KeyShareEntry,
) (extension.Value, bool, bool) {
	typ := value.ExtensionType()
	if typ == extension.TypeEarlyData {
		return nil, false, true
	}
	if typ == extension.TypeKeyShare && request.HasSelectedGroup {
		return retryKeyShare(freshShare), true, false
	}
	if typ == extension.TypeCookie && request.HasCookie {
		return &extension13.Cookie{Cookie: bytes.Clone(request.Cookie)}, true, false
	}

	return nil, false, false
}

func insertMissingRetryExtensions(
	values []extension.Value,
	request RetryRequest,
	freshShare *extension13.KeyShareEntry,
	keyShareApplied, cookieApplied bool,
) []extension.Value {
	insert := make([]extension.Value, 0, 2)
	if request.HasSelectedGroup && !keyShareApplied {
		insert = append(insert, retryKeyShare(freshShare))
	}
	if request.HasCookie && !cookieApplied {
		insert = append(insert, &extension13.Cookie{Cookie: bytes.Clone(request.Cookie)})
	}
	if len(insert) == 0 {
		return values
	}
	insertAt := len(values)
	if insertAt > 0 && values[insertAt-1].ExtensionType() == extension.TypePreSharedKey {
		insertAt--
	}

	return slices.Insert(values, insertAt, insert...)
}

func validateRetryClientHello(initial, retry ClientHelloSnapshot, request RetryRequest) error {
	if !bytes.Equal(initial.body[:initial.extensionOffset], retry.body[:retry.extensionOffset]) {
		return negotiationError(dtlserrors.ErrInvalidClientHello, errRetryChangedFields, alert.IllegalParameter)
	}
	if err := validateRetryKeyShare(retry, request); err != nil {
		return err
	}
	if err := validateRetryCookie(retry, request); err != nil {
		return err
	}
	if retryExtensionsMatch(initial, retry, request) {
		return nil
	}

	return negotiationError(dtlserrors.ErrInvalidClientHello, errRetryChangedExtensions, alert.IllegalParameter)
}

func validateRetryKeyShare(retry ClientHelloSnapshot, request RetryRequest) error {
	if !request.HasSelectedGroup {
		return nil
	}
	shares, err := clientKeyShares(retry)
	if err == nil && len(shares) == 1 && shares[0].Group == request.SelectedGroup {
		return nil
	}

	return negotiationError(dtlserrors.ErrInvalidClientHello, errRetryWrongKeyShare, alert.IllegalParameter)
}

func validateRetryCookie(retry ClientHelloSnapshot, request RetryRequest) error {
	if !request.HasCookie {
		return nil
	}
	cookie, present := retry.Extension(extension.TypeCookie)
	payload, err := (extension13.Cookie{Cookie: request.Cookie}).MarshalData()
	if err == nil && present && bytes.Equal(cookie.Data, payload) {
		return nil
	}

	return negotiationError(
		dtlserrors.ErrInvalidClientHello,
		fmt.Errorf("ClientHello2 did not echo the HelloRetryRequest cookie: %w", dtlserrors.ErrCookieMismatch),
		alert.IllegalParameter,
	)
}

func retryExtensionsMatch(initial, retry ClientHelloSnapshot, request RetryRequest) bool {
	first := comparableRetryExtensions(initial.extensions, true, request)
	second := comparableRetryExtensions(retry.extensions, false, request)

	return slices.EqualFunc(first, second, func(a, b extension.Raw) bool {
		return a.Type == b.Type && bytes.Equal(a.Data, b.Data)
	})
}

func comparableRetryExtensions(
	values []extension.Raw,
	initial bool,
	request RetryRequest,
) []extension.Raw {
	result := make([]extension.Raw, 0, len(values))
	for _, value := range values {
		if value.Type == extension.TypePadding ||
			(value.Type == extension.TypeEarlyData && initial) ||
			(value.Type == extension.TypeKeyShare && request.HasSelectedGroup) ||
			(value.Type == extension.TypeCookie && request.HasCookie) {
			continue
		}
		result = append(result, value)
	}

	return result
}

func clientKeyShares(snapshot ClientHelloSnapshot) ([]extension13.KeyShareEntry, error) {
	raw, ok := snapshot.Extension(extension.TypeKeyShare)
	if !ok {
		return nil, nil
	}
	var keyShare extension13.ClientKeyShare
	if err := keyShare.UnmarshalData(raw.Data); err != nil {
		return nil, err
	}

	return keyShare.Shares, nil
}

func helloVerifyClientHelloParts(snapshot ClientHelloSnapshot) (beforeCookie, afterCookie, cookie []byte) {
	cookieOffset := 2 + handshake.RandomLength
	cookieOffset += 1 + int(snapshot.body[cookieOffset])
	cookieStart := cookieOffset + 1
	cookieEnd := cookieStart + int(snapshot.body[cookieOffset])

	return snapshot.body[:cookieOffset], snapshot.body[cookieEnd:snapshot.extensionOffset],
		snapshot.body[cookieStart:cookieEnd]
}

func validateHelloVerifyExtension(initial, retry ClientHelloSnapshot, typ extension.Type) error {
	first, firstPresent := initial.Extension(typ)
	second, secondPresent := retry.Extension(typ)
	if firstPresent == secondPresent && bytes.Equal(first.Data, second.Data) {
		return nil
	}

	return negotiationError(
		dtlserrors.ErrInvalidClientHello,
		fmt.Errorf("%w: %d", errHelloVerifyExtensionChanged, typ),
		alert.IllegalParameter,
	)
}

func retryKeyShare(share *extension13.KeyShareEntry) *extension13.ClientKeyShare {
	return &extension13.ClientKeyShare{Shares: []extension13.KeyShareEntry{{
		Group: share.Group, KeyExchange: bytes.Clone(share.KeyExchange),
	}}}
}
