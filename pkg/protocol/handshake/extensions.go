// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"bytes"

	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
)

// extensionContext identifies the payload form of context-dependent extension
// payloads.
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

type extensionPayloadValue interface {
	extension.Value
	extension.PayloadUnmarshaller
}

func decodeExtensionList(data []byte, context extensionContext) ([]extension.Value, error) {
	rawExtensions, err := extension.ParseList(data)
	if err != nil {
		return nil, err
	}

	return decodeRawExtensions(rawExtensions, context)
}

func decodeRawExtensions(rawExtensions []extension.Raw, context extensionContext) ([]extension.Value, error) {
	values := make([]extension.Value, 0, len(rawExtensions))
	for _, raw := range rawExtensions {
		value := extensionValueForContext(context, raw.Type)
		if value == nil {
			values = append(values, raw)

			continue
		}
		if err := value.UnmarshalData(raw.Data); err != nil {
			return nil, err
		}
		values = append(values, value)
	}

	return values, nil
}

//nolint:gocyclo,cyclop
func extensionValueForContext(context extensionContext, typ extension.Type) extensionPayloadValue {
	switch context {
	case extensionContextClientHello:
		switch typ {
		case extension.TypeServerName:
			return &extension.ServerNameOffer{}
		case extension.TypeALPN:
			return &extension.ALPNOffer{}
		case extension.TypeUseSRTP:
			return &extension.SRTPOffer{}
		case extension.TypeConnectionID:
			return &extension.ConnectionID{}
		case extension.TypeSupportedGroups:
			return &extension.SupportedGroups{}
		case extension.TypeSignatureAlgorithms:
			return &extension.SignatureAlgorithms{}
		case extension.TypeSignatureAlgorithmsCert:
			return &extension.CertificateSignatureAlgorithms{}
		case extension.TypeSupportedPointFormats:
			return &extension12.SupportedPointFormats{}
		case extension.TypeExtendedMasterSecret:
			return &extension12.ExtendedMasterSecret{}
		case extension.TypeRenegotiationInfo:
			return &extension12.RenegotiationInfo{}
		case extension.TypeSupportedVersions:
			return &extension13.OfferedVersions{}
		case extension.TypeCookie:
			return &extension13.Cookie{}
		case extension.TypeKeyShare:
			return &extension13.ClientKeyShare{}
		case extension.TypePreSharedKey:
			return &extension13.OfferedPSKs{}
		case extension.TypePSKKeyExchangeModes:
			return &extension13.PSKKeyExchangeModes{}
		case extension.TypeEarlyData:
			return &extension13.EarlyData{}
		case extension.TypeCertificateAuthorities:
			return &extension13.CertificateAuthorities{}
		case extension.TypePostHandshakeAuth:
			return &extension13.PostHandshakeAuth{}
		}
	case extensionContextServerHello12:
		switch typ {
		case extension.TypeServerName:
			return &extension.ServerNameAck{}
		case extension.TypeALPN:
			return &extension.ALPNSelection{}
		case extension.TypeUseSRTP:
			return &extension.SRTPSelection{}
		case extension.TypeConnectionID:
			return &extension.ConnectionID{}
		case extension.TypeSupportedPointFormats:
			return &extension12.SupportedPointFormats{}
		case extension.TypeExtendedMasterSecret:
			return &extension12.ExtendedMasterSecret{}
		case extension.TypeRenegotiationInfo:
			return &extension12.RenegotiationInfo{}
		}
	case extensionContextServerHello13:
		switch typ {
		case extension.TypeSupportedVersions:
			return &extension13.SelectedVersion{}
		case extension.TypeKeyShare:
			return &extension13.ServerKeyShare{}
		case extension.TypePreSharedKey:
			return &extension13.SelectedPSK{}
		case extension.TypeConnectionID:
			return &extension.ConnectionID{}
		}
	case extensionContextHelloRetryRequest:
		switch typ {
		case extension.TypeSupportedVersions:
			return &extension13.SelectedVersion{}
		case extension.TypeKeyShare:
			return &extension13.RetryKeyShare{}
		case extension.TypeCookie:
			return &extension13.Cookie{}
		case extension.TypeConnectionID:
			return &extension.ConnectionID{}
		}
	case extensionContextEncryptedExtensions:
		switch typ {
		case extension.TypeServerName:
			return &extension.ServerNameAck{}
		case extension.TypeALPN:
			return &extension.ALPNSelection{}
		case extension.TypeUseSRTP:
			return &extension.SRTPSelection{}
		case extension.TypeSupportedGroups:
			return &extension.SupportedGroups{}
		case extension.TypeEarlyData:
			return &extension13.EarlyData{}
		}
	case extensionContextCertificateRequest:
		switch typ {
		case extension.TypeSignatureAlgorithms:
			return &extension.SignatureAlgorithms{}
		case extension.TypeSignatureAlgorithmsCert:
			return &extension.CertificateSignatureAlgorithms{}
		case extension.TypeCertificateAuthorities:
			return &extension13.CertificateAuthorities{}
		case extension.TypeOIDFilters:
			return &extension13.OIDFilters{}
		}
	case extensionContextNewSessionTicket:
		if typ == extension.TypeEarlyData {
			return &extension13.MaxEarlyData{}
		}
	case extensionContextCertificateEntry:
		// Not supported yet, this case is just added for the exhaustive linter.
	}

	return nil
}

func serverHelloExtensionContext(random Random, rawExtensions []extension.Raw) extensionContext {
	randomBytes := random.MarshalFixed()
	if bytes.Equal(randomBytes[:], HelloRetryRequestRandom()) {
		return extensionContextHelloRetryRequest
	}

	for _, raw := range rawExtensions {
		if raw.Type == extension.TypeSupportedVersions {
			return extensionContextServerHello13
		}
	}

	return extensionContextServerHello12
}
