// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"
	"fmt"
	"slices"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
)

// extensionContext identifies the handshake-message context in which an
// extension appears
//
// "The table below indicates the messages where a given extension may appear,
// using the following notation: CH (ClientHello), SH (ServerHello), EE
// (EncryptedExtensions), CT (Certificate), CR (CertificateRequest), NST
// (NewSessionTicket), and HRR (HelloRetryRequest)."
//
// https://www.rfc-editor.org/rfc/rfc9846#section-4.3
//
// CertificateEntry is the representation of the CT context.
// ServerHello is split because DTLS 1.2 and DTLS 1.3
// different extension sets.
// https://www.rfc-editor.org/rfc/rfc9147#section-5.3
type extensionContext uint8

const (
	extensionContextClientHello extensionContext = iota
	extensionContextServerHello12
	extensionContextServerHello13
	extensionContextHelloRetryRequest
	extensionContextEncryptedExtensions
	extensionContextCertificateRequest
	extensionContextCertificateEntry
	extensionContextNewSessionTicket
)

func (c extensionContext) String() string {
	switch c {
	case extensionContextClientHello:
		return "ClientHello"
	case extensionContextServerHello12:
		return "DTLS 1.2 ServerHello"
	case extensionContextServerHello13:
		return "DTLS 1.3 ServerHello"
	case extensionContextHelloRetryRequest:
		return "HelloRetryRequest"
	case extensionContextEncryptedExtensions:
		return "EncryptedExtensions"
	case extensionContextCertificateRequest:
		return "CertificateRequest"
	case extensionContextCertificateEntry:
		return "CertificateEntry"
	case extensionContextNewSessionTicket:
		return "NewSessionTicket"
	default:
		return "unknown handshake message"
	}
}

type extensionPayloadValue interface {
	extension.Value
	extension.PayloadUnmarshaller
}

type extensionPayloadFactory func() extensionPayloadValue

// "If an implementation receives an extension which it recognizes
// and which is not specified for the message in which it appears,
// it MUST abort the handshake with an 'illegal_parameter' alert."
//
// https://www.rfc-editor.org/rfc/rfc9846#section-4.3
//
//nolint:gochecknoglobals
var extensionRegistry = map[extension.Type]map[extensionContext]extensionPayloadFactory{
	extension.TypeServerName: {
		extensionContextClientHello:         func() extensionPayloadValue { return &extension.ServerNameOffer{} },
		extensionContextServerHello12:       func() extensionPayloadValue { return &extension.ServerNameAck{} },
		extensionContextEncryptedExtensions: func() extensionPayloadValue { return &extension.ServerNameAck{} },
	},
	extension.TypeSupportedGroups: {
		extensionContextClientHello:         func() extensionPayloadValue { return &extension.SupportedGroups{} },
		extensionContextEncryptedExtensions: func() extensionPayloadValue { return &extension.SupportedGroups{} },
	},
	extension.TypeSupportedPointFormats: {
		extensionContextClientHello:   func() extensionPayloadValue { return &extension12.SupportedPointFormats{} },
		extensionContextServerHello12: func() extensionPayloadValue { return &extension12.SupportedPointFormats{} },
	},
	extension.TypeSignatureAlgorithms: {
		extensionContextClientHello:        func() extensionPayloadValue { return &extension.SignatureAlgorithms{} },
		extensionContextCertificateRequest: func() extensionPayloadValue { return &extension.SignatureAlgorithms{} },
	},
	extension.TypeUseSRTP: {
		extensionContextClientHello:         func() extensionPayloadValue { return &extension.SRTPOffer{} },
		extensionContextServerHello12:       func() extensionPayloadValue { return &extension.SRTPSelection{} },
		extensionContextEncryptedExtensions: func() extensionPayloadValue { return &extension.SRTPSelection{} },
	},
	extension.TypeALPN: {
		extensionContextClientHello:         func() extensionPayloadValue { return &extension.ALPNOffer{} },
		extensionContextServerHello12:       func() extensionPayloadValue { return &extension.ALPNSelection{} },
		extensionContextEncryptedExtensions: func() extensionPayloadValue { return &extension.ALPNSelection{} },
	},
	extension.TypeExtendedMasterSecret: {
		extensionContextClientHello:   func() extensionPayloadValue { return &extension12.ExtendedMasterSecret{} },
		extensionContextServerHello12: func() extensionPayloadValue { return &extension12.ExtendedMasterSecret{} },
	},
	extension.TypePreSharedKey: {
		extensionContextClientHello:   func() extensionPayloadValue { return &extension13.OfferedPSKs{} },
		extensionContextServerHello13: func() extensionPayloadValue { return &extension13.SelectedPSK{} },
	},
	extension.TypeEarlyData: {
		extensionContextClientHello:         func() extensionPayloadValue { return &extension13.EarlyData{} },
		extensionContextEncryptedExtensions: func() extensionPayloadValue { return &extension13.EarlyData{} },
		extensionContextNewSessionTicket:    func() extensionPayloadValue { return &extension13.MaxEarlyData{} },
	},
	extension.TypeSupportedVersions: {
		extensionContextClientHello:       func() extensionPayloadValue { return &extension13.OfferedVersions{} },
		extensionContextServerHello13:     func() extensionPayloadValue { return &extension13.SelectedVersion{} },
		extensionContextHelloRetryRequest: func() extensionPayloadValue { return &extension13.SelectedVersion{} },
	},
	extension.TypeCookie: {
		extensionContextClientHello:       func() extensionPayloadValue { return &extension13.Cookie{} },
		extensionContextHelloRetryRequest: func() extensionPayloadValue { return &extension13.Cookie{} },
	},
	extension.TypePSKKeyExchangeModes: {
		extensionContextClientHello: func() extensionPayloadValue { return &extension13.PSKKeyExchangeModes{} },
	},
	extension.TypeCertificateAuthorities: {
		extensionContextClientHello:        func() extensionPayloadValue { return &extension13.CertificateAuthorities{} },
		extensionContextCertificateRequest: func() extensionPayloadValue { return &extension13.CertificateAuthorities{} },
	},
	extension.TypeOIDFilters: {
		extensionContextCertificateRequest: func() extensionPayloadValue { return &extension13.OIDFilters{} },
	},
	extension.TypePostHandshakeAuth: {
		extensionContextClientHello: func() extensionPayloadValue { return &extension13.PostHandshakeAuth{} },
	},
	extension.TypeSignatureAlgorithmsCert: {
		extensionContextClientHello: func() extensionPayloadValue {
			return &extension.CertificateSignatureAlgorithms{}
		},
		extensionContextCertificateRequest: func() extensionPayloadValue {
			return &extension.CertificateSignatureAlgorithms{}
		},
	},
	extension.TypeKeyShare: {
		extensionContextClientHello:       func() extensionPayloadValue { return &extension13.ClientKeyShare{} },
		extensionContextServerHello13:     func() extensionPayloadValue { return &extension13.ServerKeyShare{} },
		extensionContextHelloRetryRequest: func() extensionPayloadValue { return &extension13.RetryKeyShare{} },
	},
	extension.TypeConnectionID: {
		extensionContextClientHello:   func() extensionPayloadValue { return &extension.ConnectionID{} },
		extensionContextServerHello12: func() extensionPayloadValue { return &extension.ConnectionID{} },
		extensionContextServerHello13: func() extensionPayloadValue { return &extension.ConnectionID{} },
	},
	extension.TypeReturnRoutabilityCheck: {
		extensionContextClientHello:   func() extensionPayloadValue { return &extension.ReturnRoutabilityCheck{} },
		extensionContextServerHello12: func() extensionPayloadValue { return &extension.ReturnRoutabilityCheck{} },
		extensionContextServerHello13: func() extensionPayloadValue { return &extension.ReturnRoutabilityCheck{} },
	},
	extension.TypeRenegotiationInfo: {
		extensionContextClientHello:   func() extensionPayloadValue { return &extension12.RenegotiationInfo{} },
		extensionContextServerHello12: func() extensionPayloadValue { return &extension12.RenegotiationInfo{} },
	},
}

func decodeExtensionList(data []byte, context extensionContext) ([]extension.Value, error) {
	rawExtensions, err := extension.ParseList(data)
	if err != nil {
		return nil, fmt.Errorf(
			"extensions in %s: %w: %w",
			context,
			err,
			&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
		)
	}

	return decodeRawExtensions(rawExtensions, context)
}

func decodeRawExtensions(rawExtensions []extension.Raw, context extensionContext) ([]extension.Value, error) {
	if err := validateRawExtensionBlock(rawExtensions, context); err != nil {
		return nil, err
	}

	values := make([]extension.Value, 0, len(rawExtensions))
	for _, raw := range rawExtensions {
		contexts, known := extensionRegistry[raw.Type]
		if !known {
			values = append(values, extension.Raw{Type: raw.Type, Data: bytes.Clone(raw.Data)})

			continue
		}

		factory, allowed := contexts[context]
		if !allowed {
			return nil, fmt.Errorf(
				"extension %d in %s: %w: %w",
				raw.Type,
				context,
				dtlserrors.ErrExtensionNotAllowed,
				&alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
			)
		}
		if factory == nil {
			values = append(values, extension.Raw{Type: raw.Type, Data: bytes.Clone(raw.Data)})

			continue
		}

		value := factory()
		if err := value.UnmarshalData(raw.Data); err != nil {
			return nil, fmt.Errorf(
				"extension %d in %s: %w: %w",
				raw.Type,
				context,
				err,
				&alert.Alert{Level: alert.Fatal, Description: alert.DecodeError},
			)
		}
		values = append(values, value)
	}

	if err := validateExtensionDependencies(values, context); err != nil {
		return nil, err
	}

	return values, nil
}

func validateRawExtensionBlock(rawExtensions []extension.Raw, context extensionContext) error {
	seen := make(map[extension.Type]struct{}, len(rawExtensions))
	for _, raw := range rawExtensions {
		if _, ok := seen[raw.Type]; ok {
			return fmt.Errorf(
				"extension %d in %s: %w: %w",
				raw.Type,
				context,
				dtlserrors.ErrDuplicateExtension,
				&alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
			)
		}
		seen[raw.Type] = struct{}{}
	}

	if context == extensionContextClientHello {
		for i, raw := range rawExtensions {
			if raw.Type == extension.TypePreSharedKey && i != len(rawExtensions)-1 {
				return fmt.Errorf(
					"extension %d in %s: %w: %w",
					raw.Type,
					context,
					dtlserrors.ErrPreSharedKeyNotLast,
					&alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
				)
			}
		}
	}

	for _, raw := range rawExtensions {
		if contexts, known := extensionRegistry[raw.Type]; known {
			if _, allowed := contexts[context]; !allowed {
				return fmt.Errorf(
					"extension %d in %s: %w: %w",
					raw.Type,
					context,
					dtlserrors.ErrExtensionNotAllowed,
					&alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
				)
			}
		}
	}

	return nil
}

type extensionDependencyValues struct {
	present  map[extension.Type]bool
	groups   *extension.SupportedGroups
	keyShare *extension13.ClientKeyShare
	versions *extension13.OfferedVersions
}

func validateExtensionDependencies(values []extension.Value, context extensionContext) error {
	dependencies := collectExtensionDependencies(values)
	if err := validateSupportedGroups(dependencies.groups, context); err != nil {
		return err
	}

	//nolint:exhaustive // Only these contexts define cross-extension requirements.
	switch context {
	case extensionContextClientHello:
		return validateClientHelloDependencies(dependencies)
	case extensionContextHelloRetryRequest:
		return validateHelloRetryRequestDependencies(dependencies)
	case extensionContextCertificateRequest:
		return validateCertificateRequestDependencies(dependencies)
	}

	return nil
}

func collectExtensionDependencies(values []extension.Value) extensionDependencyValues {
	dependencies := extensionDependencyValues{present: make(map[extension.Type]bool, len(values))}
	for _, value := range values {
		dependencies.present[value.ExtensionType()] = true
		switch typed := value.(type) {
		case *extension.SupportedGroups:
			dependencies.groups = typed
		case *extension13.ClientKeyShare:
			dependencies.keyShare = typed
		case *extension13.OfferedVersions:
			dependencies.versions = typed
		}
	}

	return dependencies
}

func validateSupportedGroups(groups *extension.SupportedGroups, context extensionContext) error {
	if groups == nil || supportedGroupsUnique(groups) {
		return nil
	}

	return fmt.Errorf(
		"extension %d in %s: %w: %w",
		extension.TypeSupportedGroups,
		context,
		dtlserrors.ErrDuplicateSupportedGroup,
		&alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
	)
}

func validateClientHelloDependencies(dependencies extensionDependencyValues) error {
	if err := validatePSKDependencies(dependencies); err != nil {
		return err
	}
	if dependencies.present[extension.TypeReturnRoutabilityCheck] &&
		!dependencies.present[extension.TypeConnectionID] {
		return fmt.Errorf(
			"extension %d in %s requires extension %d: %w: %w",
			extension.TypeReturnRoutabilityCheck,
			extensionContextClientHello,
			extension.TypeConnectionID,
			dtlserrors.ErrMissingConnectionIDExtension,
			&alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension},
		)
	}
	if err := validateTLS13ClientHelloDependencies(dependencies); err != nil {
		return err
	}
	if dependencies.keyShare == nil || dependencies.groups == nil ||
		keyShareGroupsFollowSupportedGroups(dependencies.keyShare, dependencies.groups) {
		return nil
	}

	return fmt.Errorf(
		"extension %d in %s: %w: %w",
		extension.TypeKeyShare,
		extensionContextClientHello,
		dtlserrors.ErrKeyShareGroupNotOffered,
		&alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
	)
}

func validatePSKDependencies(dependencies extensionDependencyValues) error {
	if dependencies.present[extension.TypePreSharedKey] && !dependencies.present[extension.TypePSKKeyExchangeModes] {
		return fmt.Errorf(
			"extension %d in %s: %w: %w",
			extension.TypePSKKeyExchangeModes,
			extensionContextClientHello,
			dtlserrors.ErrMissingPSKKeyExchangeModesExtension,
			&alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension},
		)
	}
	if dependencies.present[extension.TypeEarlyData] && !dependencies.present[extension.TypePreSharedKey] {
		return fmt.Errorf(
			"extension %d in %s: %w: %w",
			extension.TypeEarlyData,
			extensionContextClientHello,
			dtlserrors.ErrEarlyDataWithoutPreSharedKey,
			&alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter},
		)
	}

	return nil
}

func validateTLS13ClientHelloDependencies(dependencies extensionDependencyValues) error {
	attempts13 := dependencies.versions != nil &&
		slices.Contains(dependencies.versions.Versions, protocol.Version1_3)
	if !attempts13 {
		return nil
	}
	if dependencies.groups != nil && dependencies.keyShare == nil {
		return fmt.Errorf(
			"extension %d in %s: %w: %w",
			extension.TypeKeyShare,
			extensionContextClientHello,
			dtlserrors.ErrSupportedGroupsWithoutKeyShare,
			&alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension},
		)
	}
	if dependencies.keyShare != nil && dependencies.groups == nil {
		return fmt.Errorf(
			"extension %d in %s: %w: %w",
			extension.TypeSupportedGroups,
			extensionContextClientHello,
			dtlserrors.ErrKeyShareWithoutSupportedGroups,
			&alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension},
		)
	}
	if dependencies.present[extension.TypePreSharedKey] ||
		(dependencies.present[extension.TypeSignatureAlgorithms] && dependencies.groups != nil) {
		return nil
	}

	return fmt.Errorf(
		"extensions in %s: %w: %w",
		extensionContextClientHello,
		dtlserrors.ErrMissingClientHelloExtension,
		&alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension},
	)
}

func validateHelloRetryRequestDependencies(dependencies extensionDependencyValues) error {
	if dependencies.present[extension.TypeSupportedVersions] {
		return nil
	}

	return fmt.Errorf(
		"extension %d in %s: %w: %w",
		extension.TypeSupportedVersions,
		extensionContextHelloRetryRequest,
		dtlserrors.ErrMissingSupportedVersionsExtension,
		&alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension},
	)
}

func validateCertificateRequestDependencies(dependencies extensionDependencyValues) error {
	if dependencies.present[extension.TypeSignatureAlgorithms] {
		return nil
	}

	return fmt.Errorf(
		"extension %d in %s: %w: %w",
		extension.TypeSignatureAlgorithms,
		extensionContextCertificateRequest,
		dtlserrors.ErrMissingSignatureAlgorithmsExtension,
		&alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension},
	)
}

func supportedGroupsUnique(groups *extension.SupportedGroups) bool {
	seen := make(map[elliptic.Curve]struct{}, len(groups.Groups))
	for _, group := range groups.Groups {
		if _, ok := seen[group]; ok {
			return false
		}
		seen[group] = struct{}{}
	}

	return true
}

func keyShareGroupsFollowSupportedGroups(
	keyShare *extension13.ClientKeyShare,
	groups *extension.SupportedGroups,
) bool {
	nextGroup := 0
	for _, share := range keyShare.Shares {
		found := false
		for nextGroup < len(groups.Groups) {
			group := groups.Groups[nextGroup]
			nextGroup++
			if group == share.Group {
				found = true

				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func serverHelloExtensionContext(random Random, rawExtensions []extension.Raw) extensionContext {
	randomBytes := random.MarshalFixed()
	if bytes.Equal(randomBytes[:], HelloRetryRequestRandom()) {
		return extensionContextHelloRetryRequest
	}

	for _, raw := range rawExtensions {
		//nolint:exhaustive // Only extensions unique to DTLS 1.3 identify this context.
		switch raw.Type {
		case extension.TypeSupportedVersions, extension.TypeKeyShare, extension.TypePreSharedKey:
			return extensionContextServerHello13
		}
	}

	return extensionContextServerHello12
}
