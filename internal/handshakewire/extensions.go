// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshakewire

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/pion/dtls/v4/internal/clienthello"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls12"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
)

// Context identifies the handshake-message context in which an
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
type Context uint8

const (
	ContextClientHello Context = iota
	ContextServerHello12
	ContextServerHello13
	ContextHelloRetryRequest
	ContextEncryptedExtensions
	ContextCertificateRequest
	ContextCertificateEntry
	ContextNewSessionTicket
)

func (c Context) String() string {
	switch c {
	case ContextClientHello:
		return "ClientHello"
	case ContextServerHello12:
		return "DTLS 1.2 ServerHello"
	case ContextServerHello13:
		return "DTLS 1.3 ServerHello"
	case ContextHelloRetryRequest:
		return "HelloRetryRequest"
	case ContextEncryptedExtensions:
		return "EncryptedExtensions"
	case ContextCertificateRequest:
		return "CertificateRequest"
	case ContextCertificateEntry:
		return "CertificateEntry"
	case ContextNewSessionTicket:
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
var extensionRegistry = map[extension.Type]map[Context]extensionPayloadFactory{
	extension.TypeServerName: {
		ContextClientHello:         func() extensionPayloadValue { return &extension.ServerNameOffer{} },
		ContextServerHello12:       func() extensionPayloadValue { return &extension.ServerNameAck{} },
		ContextEncryptedExtensions: func() extensionPayloadValue { return &extension.ServerNameAck{} },
	},
	extension.TypeSupportedGroups:       {ContextClientHello: func() extensionPayloadValue { return &extension.SupportedGroups{} }, ContextEncryptedExtensions: func() extensionPayloadValue { return &extension.SupportedGroups{} }},
	extension.TypeSupportedPointFormats: {ContextClientHello: func() extensionPayloadValue { return &extension12.SupportedPointFormats{} }, ContextServerHello12: func() extensionPayloadValue { return &extension12.SupportedPointFormats{} }},
	extension.TypeSignatureAlgorithms:   {ContextClientHello: func() extensionPayloadValue { return &extension.SignatureAlgorithms{} }, ContextCertificateRequest: func() extensionPayloadValue { return &extension.SignatureAlgorithms{} }},
	extension.TypeUseSRTP: {
		ContextClientHello:         func() extensionPayloadValue { return &extension.SRTPOffer{} },
		ContextServerHello12:       func() extensionPayloadValue { return &extension.SRTPSelection{} },
		ContextEncryptedExtensions: func() extensionPayloadValue { return &extension.SRTPSelection{} },
	},
	extension.TypeALPN: {
		ContextClientHello:         func() extensionPayloadValue { return &extension.ALPNOffer{} },
		ContextServerHello12:       func() extensionPayloadValue { return &extension.ALPNSelection{} },
		ContextEncryptedExtensions: func() extensionPayloadValue { return &extension.ALPNSelection{} },
	},
	extension.TypeExtendedMasterSecret: {ContextClientHello: func() extensionPayloadValue { return &extension12.ExtendedMasterSecret{} }, ContextServerHello12: func() extensionPayloadValue { return &extension12.ExtendedMasterSecret{} }},
	extension.TypePreSharedKey:         {ContextClientHello: func() extensionPayloadValue { return &extension13.OfferedPSKs{} }, ContextServerHello13: func() extensionPayloadValue { return &extension13.SelectedPSK{} }},
	extension.TypeEarlyData: {
		ContextClientHello:         func() extensionPayloadValue { return &extension13.EarlyData{} },
		ContextEncryptedExtensions: func() extensionPayloadValue { return &extension13.EarlyData{} },
		ContextNewSessionTicket:    func() extensionPayloadValue { return &extension13.MaxEarlyData{} },
	},
	extension.TypeSupportedVersions: {
		ContextClientHello:       func() extensionPayloadValue { return &extension13.OfferedVersions{} },
		ContextServerHello13:     func() extensionPayloadValue { return &extension13.SelectedVersion{} },
		ContextHelloRetryRequest: func() extensionPayloadValue { return &extension13.SelectedVersion{} },
	},
	extension.TypeCookie:                  {ContextClientHello: func() extensionPayloadValue { return &extension13.Cookie{} }, ContextHelloRetryRequest: func() extensionPayloadValue { return &extension13.Cookie{} }},
	extension.TypePSKKeyExchangeModes:     {ContextClientHello: func() extensionPayloadValue { return &extension13.PSKKeyExchangeModes{} }},
	extension.TypeCertificateAuthorities:  {ContextClientHello: func() extensionPayloadValue { return &extension13.CertificateAuthorities{} }, ContextCertificateRequest: func() extensionPayloadValue { return &extension13.CertificateAuthorities{} }},
	extension.TypeOIDFilters:              {ContextCertificateRequest: func() extensionPayloadValue { return &extension13.OIDFilters{} }},
	extension.TypePostHandshakeAuth:       {ContextClientHello: func() extensionPayloadValue { return &extension13.PostHandshakeAuth{} }},
	extension.TypeSignatureAlgorithmsCert: {ContextClientHello: func() extensionPayloadValue { return &extension.CertificateSignatureAlgorithms{} }, ContextCertificateRequest: func() extensionPayloadValue { return &extension.CertificateSignatureAlgorithms{} }},
	extension.TypeKeyShare: {
		ContextClientHello:       func() extensionPayloadValue { return &extension13.ClientKeyShare{} },
		ContextServerHello13:     func() extensionPayloadValue { return &extension13.ServerKeyShare{} },
		ContextHelloRetryRequest: func() extensionPayloadValue { return &extension13.RetryKeyShare{} },
	},
	extension.TypeConnectionID: {
		ContextClientHello:   func() extensionPayloadValue { return &extension.ConnectionID{} },
		ContextServerHello12: func() extensionPayloadValue { return &extension.ConnectionID{} },
		ContextServerHello13: func() extensionPayloadValue { return &extension.ConnectionID{} },
	},
	extension.TypeReturnRoutabilityCheck: {
		ContextClientHello:   func() extensionPayloadValue { return &extension.ReturnRoutabilityCheck{} },
		ContextServerHello12: func() extensionPayloadValue { return &extension.ReturnRoutabilityCheck{} },
		ContextServerHello13: func() extensionPayloadValue { return &extension.ReturnRoutabilityCheck{} },
	},
	extension.TypeRenegotiationInfo: {ContextClientHello: func() extensionPayloadValue { return &extension12.RenegotiationInfo{} }, ContextServerHello12: func() extensionPayloadValue { return &extension12.RenegotiationInfo{} }},
}

// DecodeExtensionList decodes an extension list for a handshake message context.
func DecodeExtensionList(data []byte, context Context) ([]extension.Value, error) {
	rawExtensions, err := extension.ParseList(data)
	if err != nil {
		return nil, fmt.Errorf("extensions in %s: %w: %w", context, err, &alert.Alert{Level: alert.Fatal, Description: alert.DecodeError})
	}

	return DecodeRawExtensions(rawExtensions, context)
}

// DecodeRawExtensions decodes and validates extensions for a handshake message context.
func DecodeRawExtensions(rawExtensions []extension.Raw, context Context) ([]extension.Value, error) {
	if err := validateRawExtensionBlock(rawExtensions, context); err != nil {
		return nil, err
	}

	values := make([]extension.Value, 0, len(rawExtensions))
	for _, raw := range rawExtensions {
		// Context validity was checked above; unknown types have no decoder.
		factory := extensionRegistry[raw.Type][context]
		if factory == nil {
			values = append(values, extension.Raw{Type: raw.Type, Data: bytes.Clone(raw.Data)})

			continue
		}

		value := factory()
		if err := value.UnmarshalData(raw.Data); err != nil {
			return nil, fmt.Errorf("extension %d in %s: %w: %w", raw.Type, context, err, &alert.Alert{Level: alert.Fatal, Description: alert.DecodeError})
		}
		values = append(values, value)
	}

	if err := validateExtensionDependencies(values, context); err != nil {
		return nil, err
	}

	return values, nil
}

func validateRawExtensionBlock(rawExtensions []extension.Raw, context Context) error {
	if err := clienthello.ValidateExtensions(rawExtensions, context == ContextClientHello); err != nil {
		return fmt.Errorf("extensions in %s: %w: %w", context, err, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter})
	}

	for _, raw := range rawExtensions {
		if contexts, known := extensionRegistry[raw.Type]; known {
			if _, allowed := contexts[context]; !allowed {
				return fmt.Errorf("extension %d in %s: %w: %w", raw.Type, context, dtlserrors.ErrExtensionNotAllowed, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter})
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

func validateExtensionDependencies(values []extension.Value, context Context) error {
	dependencies := collectExtensionDependencies(values)
	if err := validateSupportedGroups(dependencies.groups, context); err != nil {
		return err
	}

	//nolint:exhaustive // Only these contexts define cross-extension requirements.
	switch context {
	case ContextClientHello:
		return validateClientHelloDependencies(dependencies)
	case ContextHelloRetryRequest:
		return validateHelloRetryRequestDependencies(dependencies)
	case ContextCertificateRequest:
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

func validateSupportedGroups(groups *extension.SupportedGroups, context Context) error {
	if groups == nil || supportedGroupsUnique(groups) {
		return nil
	}

	return fmt.Errorf("extension %d in %s: %w: %w", extension.TypeSupportedGroups, context, dtlserrors.ErrDuplicateSupportedGroup, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter})
}

func validateClientHelloDependencies(dependencies extensionDependencyValues) error {
	if err := validatePSKDependencies(dependencies); err != nil {
		return err
	}
	if dependencies.present[extension.TypeReturnRoutabilityCheck] &&
		!dependencies.present[extension.TypeConnectionID] {
		return fmt.Errorf("extension %d in %s requires extension %d: %w: %w", extension.TypeReturnRoutabilityCheck, ContextClientHello, extension.TypeConnectionID, dtlserrors.ErrMissingConnectionIDExtension, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension})
	}
	if err := validateTLS13ClientHelloDependencies(dependencies); err != nil {
		return err
	}
	if dependencies.keyShare == nil || dependencies.groups == nil || keyShareGroupsFollowSupportedGroups(dependencies.keyShare, dependencies.groups) {
		return nil
	}

	return fmt.Errorf("extension %d in %s: %w: %w", extension.TypeKeyShare, ContextClientHello, dtlserrors.ErrKeyShareGroupNotOffered, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter})
}

func validatePSKDependencies(dependencies extensionDependencyValues) error {
	if dependencies.present[extension.TypePreSharedKey] && !dependencies.present[extension.TypePSKKeyExchangeModes] {
		return fmt.Errorf("extension %d in %s: %w: %w", extension.TypePSKKeyExchangeModes, ContextClientHello, dtlserrors.ErrMissingPSKKeyExchangeModesExtension, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension})
	}
	if dependencies.present[extension.TypeEarlyData] && !dependencies.present[extension.TypePreSharedKey] {
		return fmt.Errorf("extension %d in %s: %w: %w", extension.TypeEarlyData, ContextClientHello, dtlserrors.ErrEarlyDataWithoutPreSharedKey, &alert.Alert{Level: alert.Fatal, Description: alert.IllegalParameter})
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
		return fmt.Errorf("extension %d in %s: %w: %w", extension.TypeKeyShare, ContextClientHello, dtlserrors.ErrSupportedGroupsWithoutKeyShare, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension})
	}
	if dependencies.keyShare != nil && dependencies.groups == nil {
		return fmt.Errorf("extension %d in %s: %w: %w", extension.TypeSupportedGroups, ContextClientHello, dtlserrors.ErrKeyShareWithoutSupportedGroups, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension})
	}
	if dependencies.present[extension.TypePreSharedKey] || (dependencies.present[extension.TypeSignatureAlgorithms] && dependencies.groups != nil) {
		return nil
	}

	return fmt.Errorf("extensions in %s: %w: %w", ContextClientHello, dtlserrors.ErrMissingClientHelloExtension, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension})
}

func validateHelloRetryRequestDependencies(dependencies extensionDependencyValues) error {
	if dependencies.present[extension.TypeSupportedVersions] {
		return nil
	}

	return fmt.Errorf("extension %d in %s: %w: %w", extension.TypeSupportedVersions, ContextHelloRetryRequest, dtlserrors.ErrMissingSupportedVersionsExtension, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension})
}

func validateCertificateRequestDependencies(dependencies extensionDependencyValues) error {
	if dependencies.present[extension.TypeSignatureAlgorithms] {
		return nil
	}

	return fmt.Errorf("extension %d in %s: %w: %w", extension.TypeSignatureAlgorithms, ContextCertificateRequest, dtlserrors.ErrMissingSignatureAlgorithmsExtension, &alert.Alert{Level: alert.Fatal, Description: alert.MissingExtension})
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
