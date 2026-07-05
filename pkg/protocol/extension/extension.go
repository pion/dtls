// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package extension implements the extension values in the ClientHello/ServerHello
package extension

import (
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

// TypeValue is the 2 byte value for a TLS Extension as registered in the IANA
//
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
type TypeValue uint16

// TypeValue constants.
const (
	ServerNameTypeValue TypeValue = 0
	// In DTLS 1.3, this extension in renamed to "supported_groups".
	SupportedEllipticCurvesTypeValue      TypeValue = 10
	SupportedPointFormatsTypeValue        TypeValue = 11
	SupportedSignatureAlgorithmsTypeValue TypeValue = 13
	UseSRTPTypeValue                      TypeValue = 14
	ALPNTypeValue                         TypeValue = 16
	UseExtendedMasterSecretTypeValue      TypeValue = 23
	PreSharedKeyValue                     TypeValue = 41
	EarlyDataIndicationTypeValue          TypeValue = 42
	SupportedVersionsTypeValue            TypeValue = 43
	CookieTypeValue                       TypeValue = 44
	PskKeyExchangeModesTypeValue          TypeValue = 45
	CertificateAuthoritiesTypeValue       TypeValue = 47
	OIDFiltersTypeValue                   TypeValue = 48
	PostHandshakeAuthTypeValue            TypeValue = 49
	SignatureAlgorithmsCertTypeValue      TypeValue = 50
	KeyShareTypeValue                     TypeValue = 51
	ConnectionIDTypeValue                 TypeValue = 54
	RenegotiationInfoTypeValue            TypeValue = 65281
)

// Extension represents a single TLS extension.
type Extension interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
	TypeValue() TypeValue
}

type extensionPayloadUnmarshaller interface {
	unmarshalPayload(data []byte) error
}

func extensionPayload(data []byte, expected TypeValue) ([]byte, error) {
	if len(data) < 2 {
		return nil, dtlserrors.ErrBufferTooSmall
	}
	if TypeValue(binary.BigEndian.Uint16(data)) != expected {
		return nil, dtlserrors.ErrInvalidExtensionType
	}
	if len(data) < 4 {
		return nil, dtlserrors.ErrBufferTooSmall
	}

	declaredLen := int(binary.BigEndian.Uint16(data[2:4]))
	if declaredLen != len(data)-4 {
		return nil, dtlserrors.ErrLengthMismatch
	}

	return data[4:], nil
}

// Unmarshal many extensions at once.
func Unmarshal(buf []byte) ([]Extension, error) { //nolint:cyclop
	switch {
	case len(buf) == 0:
		return []Extension{}, nil
	case len(buf) < 2:
		return nil, dtlserrors.ErrBufferTooSmall
	}

	declaredLen := binary.BigEndian.Uint16(buf)
	if len(buf)-2 != int(declaredLen) {
		return nil, dtlserrors.ErrLengthMismatch
	}

	extensions := []Extension{}
	unmarshalAndAppend := func(data []byte, e Extension) error {
		if payloadUnmarshaller, ok := e.(extensionPayloadUnmarshaller); ok {
			if err := payloadUnmarshaller.unmarshalPayload(data[4:]); err != nil {
				return err
			}
		} else {
			if err := e.Unmarshal(data); err != nil {
				return err
			}
		}
		extensions = append(extensions, e)

		return nil
	}

	for offset := 2; offset < len(buf); {
		bufView := buf[offset:] //nolint:gosec // offset bounded by loop condition
		if len(bufView) < 4 {
			return nil, dtlserrors.ErrBufferTooSmall
		}

		extensionLength := int(binary.BigEndian.Uint16(bufView[2:4]))
		extensionEnd := 4 + extensionLength
		if extensionEnd > len(bufView) {
			return nil, dtlserrors.ErrLengthMismatch
		}
		extensionData := bufView[:extensionEnd]

		var err error
		switch TypeValue(binary.BigEndian.Uint16(bufView)) {
		case ServerNameTypeValue:
			err = unmarshalAndAppend(extensionData, &ServerName{})
		case SupportedEllipticCurvesTypeValue:
			err = unmarshalAndAppend(extensionData, &SupportedEllipticCurves{})
		case SupportedPointFormatsTypeValue:
			err = unmarshalAndAppend(extensionData, &SupportedPointFormats{})
		case SupportedSignatureAlgorithmsTypeValue:
			err = unmarshalAndAppend(extensionData, &SupportedSignatureAlgorithms{})
		case SignatureAlgorithmsCertTypeValue:
			err = unmarshalAndAppend(extensionData, &SignatureAlgorithmsCert{})
		case UseSRTPTypeValue:
			err = unmarshalAndAppend(extensionData, &UseSRTP{})
		case ALPNTypeValue:
			err = unmarshalAndAppend(extensionData, &ALPN{})
		case UseExtendedMasterSecretTypeValue:
			err = unmarshalAndAppend(extensionData, &UseExtendedMasterSecret{})
		case RenegotiationInfoTypeValue:
			err = unmarshalAndAppend(extensionData, &RenegotiationInfo{})
		case ConnectionIDTypeValue:
			err = unmarshalAndAppend(extensionData, &ConnectionID{})
		case SupportedVersionsTypeValue:
			err = unmarshalAndAppend(extensionData, &SupportedVersions{})
		case KeyShareTypeValue:
			err = unmarshalAndAppend(extensionData, &KeyShare{})
		case CookieTypeValue:
			err = unmarshalAndAppend(extensionData, &CookieExt{})
		case PskKeyExchangeModesTypeValue:
			err = unmarshalAndAppend(extensionData, &PskKeyExchangeModes{})
		case PreSharedKeyValue:
			err = unmarshalAndAppend(extensionData, &PreSharedKey{})
		default:
		}

		if err != nil {
			return nil, err
		}
		offset += extensionEnd
	}

	return extensions, nil
}

// Marshal many extensions at once.
func Marshal(e []Extension) ([]byte, error) {
	extensions := []byte{}
	for _, e := range e {
		raw, err := e.Marshal()
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, raw...)
	}
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out, uint16(len(extensions))) //nolint:gosec // G115

	return append(out, extensions...), nil
}
