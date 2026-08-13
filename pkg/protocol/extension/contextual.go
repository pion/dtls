// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"bytes"
	"encoding/binary"
	"strings"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
)

const serverNameTypeDNSHostName = 0

// ServerNameOffer is the ClientHello server_name payload.
type ServerNameOffer struct {
	ServerName string
}

func (ServerNameOffer) ExtensionType() Type { return TypeServerName }

func (s ServerNameOffer) MarshalData() ([]byte, error) {
	name := []byte(s.ServerName)
	if len(name) == 0 || len(name) > 0xffff-3 || strings.HasSuffix(s.ServerName, ".") {
		return nil, dtlserrors.ErrInvalidSNIFormat
	}

	out := make([]byte, 5, 5+len(name))
	binary.BigEndian.PutUint16(out, uint16(3+len(name))) //nolint:gosec // length is bounded above.
	out[2] = serverNameTypeDNSHostName
	binary.BigEndian.PutUint16(out[3:], uint16(len(name))) //nolint:gosec // length is bounded above.
	out = append(out, name...)

	return out, nil
}

func (s *ServerNameOffer) UnmarshalData(data []byte) error { //nolint:cyclop
	if len(data) < 2 || int(binary.BigEndian.Uint16(data)) != len(data)-2 || len(data) == 2 {
		return dtlserrors.ErrInvalidSNIFormat
	}
	data = data[2:]

	name := ""
	for len(data) > 0 {
		if len(data) < 3 {
			return dtlserrors.ErrInvalidSNIFormat
		}
		nameType := data[0]
		nameLen := int(binary.BigEndian.Uint16(data[1:]))
		data = data[3:]
		if nameLen == 0 || nameLen > len(data) {
			return dtlserrors.ErrInvalidSNIFormat
		}
		if nameType == serverNameTypeDNSHostName {
			if name != "" {
				return dtlserrors.ErrInvalidSNIFormat
			}
			name = string(data[:nameLen])
			if strings.HasSuffix(name, ".") {
				return dtlserrors.ErrInvalidSNIFormat
			}
		}
		data = data[nameLen:]
	}
	if name == "" {
		return dtlserrors.ErrInvalidSNIFormat
	}
	s.ServerName = name

	return nil
}

// ServerNameAck is the empty server acknowledgement payload.
type ServerNameAck struct{}

func (ServerNameAck) ExtensionType() Type              { return TypeServerName }
func (ServerNameAck) MarshalData() ([]byte, error)     { return []byte{}, nil }
func (*ServerNameAck) UnmarshalData(data []byte) error { return requireEmptyPayload(data) }

// ALPNOffer is the ClientHello application_layer_protocol_negotiation payload.
type ALPNOffer struct {
	Protocols []string
}

func (ALPNOffer) ExtensionType() Type { return TypeALPN }

func (a ALPNOffer) MarshalData() ([]byte, error) { return marshalALPNProtocols(a.Protocols) }

func (a *ALPNOffer) UnmarshalData(data []byte) error {
	protocols, err := unmarshalALPNProtocols(data)
	if err != nil {
		return err
	}
	a.Protocols = protocols

	return nil
}

// ALPNSelection is the server's single selected ALPN protocol.
type ALPNSelection struct {
	Protocol string
}

func (ALPNSelection) ExtensionType() Type { return TypeALPN }

func (a ALPNSelection) MarshalData() ([]byte, error) {
	return marshalALPNProtocols([]string{a.Protocol})
}

func (a *ALPNSelection) UnmarshalData(data []byte) error {
	protocols, err := unmarshalALPNProtocols(data)
	if err != nil || len(protocols) != 1 {
		return ErrALPNInvalidFormat
	}
	a.Protocol = protocols[0]

	return nil
}

func marshalALPNProtocols(protocols []string) ([]byte, error) {
	if len(protocols) == 0 {
		return nil, ErrALPNInvalidFormat
	}

	list := make([]byte, 0)
	for _, protocol := range protocols {
		if len(protocol) == 0 || len(protocol) > 255 || len(list) > 0xffff-1-len(protocol) {
			return nil, ErrALPNInvalidFormat
		}
		list = append(list, byte(len(protocol))) //nolint:gosec // length is bounded above.
		list = append(list, protocol...)
	}

	out := make([]byte, 2, 2+len(list))
	binary.BigEndian.PutUint16(out, uint16(len(list))) //nolint:gosec // length is bounded above.
	out = append(out, list...)

	return out, nil
}

func unmarshalALPNProtocols(data []byte) ([]string, error) {
	if len(data) < 2 || int(binary.BigEndian.Uint16(data)) != len(data)-2 || len(data) == 2 {
		return nil, ErrALPNInvalidFormat
	}
	data = data[2:]

	protocols := make([]string, 0)
	for len(data) > 0 {
		length := int(data[0])
		data = data[1:]
		if length == 0 || length > len(data) {
			return nil, ErrALPNInvalidFormat
		}
		protocols = append(protocols, string(data[:length]))
		data = data[length:]
	}

	return protocols, nil
}

// SRTPOffer is the ClientHello use_srtp payload.
type SRTPOffer struct {
	ProtectionProfiles  []SRTPProtectionProfile
	MasterKeyIdentifier []byte
}

func (SRTPOffer) ExtensionType() Type { return TypeUseSRTP }

func (s SRTPOffer) MarshalData() ([]byte, error) {
	return marshalSRTPPayload(s.ProtectionProfiles, s.MasterKeyIdentifier)
}

func (s *SRTPOffer) UnmarshalData(data []byte) error {
	profiles, mki, err := unmarshalSRTPPayload(data)
	if err != nil {
		return err
	}
	s.ProtectionProfiles, s.MasterKeyIdentifier = profiles, mki

	return nil
}

// SRTPSelection is the server's single selected SRTP profile.
type SRTPSelection struct {
	ProtectionProfile   SRTPProtectionProfile
	MasterKeyIdentifier []byte
}

func (SRTPSelection) ExtensionType() Type { return TypeUseSRTP }

func (s SRTPSelection) MarshalData() ([]byte, error) {
	return marshalSRTPPayload([]SRTPProtectionProfile{s.ProtectionProfile}, s.MasterKeyIdentifier)
}

func (s *SRTPSelection) UnmarshalData(data []byte) error {
	profiles, mki, err := unmarshalSRTPPayload(data)
	if err != nil || len(profiles) != 1 {
		return dtlserrors.ErrLengthMismatch
	}
	s.ProtectionProfile, s.MasterKeyIdentifier = profiles[0], mki

	return nil
}

func marshalSRTPPayload(profiles []SRTPProtectionProfile, mki []byte) ([]byte, error) {
	if len(profiles) == 0 || len(profiles) > 0x7fff {
		return nil, dtlserrors.ErrUseSRTPDataTooLarge
	}
	if len(mki) > 255 {
		return nil, dtlserrors.ErrMasterKeyIdentifierTooLarge
	}

	out := make([]byte, 2, 3+(len(profiles)*2)+len(mki))
	binary.BigEndian.PutUint16(out, uint16(len(profiles)*2)) //nolint:gosec // profile count is bounded above.
	for _, profile := range profiles {
		out = binary.BigEndian.AppendUint16(out, uint16(profile))
	}
	out = append(out, byte(len(mki))) //nolint:gosec // length is bounded above.
	out = append(out, mki...)

	return out, nil
}

func unmarshalSRTPPayload(data []byte) ([]SRTPProtectionProfile, []byte, error) {
	if len(data) < 3 {
		return nil, nil, dtlserrors.ErrBufferTooSmall
	}
	profilesLen := int(binary.BigEndian.Uint16(data))
	if profilesLen == 0 || profilesLen%2 != 0 || 2+profilesLen >= len(data) {
		return nil, nil, dtlserrors.ErrLengthMismatch
	}
	mkiLen := int(data[2+profilesLen])
	if 3+profilesLen+mkiLen != len(data) {
		return nil, nil, dtlserrors.ErrLengthMismatch
	}

	profiles := make([]SRTPProtectionProfile, 0, profilesLen/2)
	for offset := 2; offset < 2+profilesLen; offset += 2 {
		profiles = append(profiles, SRTPProtectionProfile(binary.BigEndian.Uint16(data[offset:])))
	}

	return profiles, bytes.Clone(data[3+profilesLen:]), nil
}

// SupportedGroups is the supported_groups payload.
type SupportedGroups struct {
	Groups []elliptic.Curve
}

func (SupportedGroups) ExtensionType() Type { return TypeSupportedGroups }

func (s SupportedGroups) MarshalData() ([]byte, error) {
	if len(s.Groups) == 0 || len(s.Groups) > 0x7fff {
		return nil, dtlserrors.ErrLengthMismatch
	}
	out := make([]byte, 2, 2+(len(s.Groups)*2))
	binary.BigEndian.PutUint16(out, uint16(len(s.Groups)*2)) //nolint:gosec // group count is bounded above.
	for _, group := range s.Groups {
		out = binary.BigEndian.AppendUint16(out, uint16(group))
	}

	return out, nil
}

func (s *SupportedGroups) UnmarshalData(data []byte) error {
	if len(data) < 4 || int(binary.BigEndian.Uint16(data)) != len(data)-2 || (len(data)-2)%2 != 0 {
		return dtlserrors.ErrLengthMismatch
	}
	s.Groups = s.Groups[:0]
	for offset := 2; offset < len(data); offset += 2 {
		s.Groups = append(s.Groups, elliptic.Curve(binary.BigEndian.Uint16(data[offset:])))
	}

	return nil
}

// SignatureAlgorithms is the signature_algorithms payload. Scheme values are
// kept as wire identifiers so unknown values are not discarded by framing.
type SignatureAlgorithms struct {
	Schemes []uint16
}

func (SignatureAlgorithms) ExtensionType() Type            { return TypeSignatureAlgorithms }
func (s SignatureAlgorithms) MarshalData() ([]byte, error) { return marshalUint16List(s.Schemes) }
func (s *SignatureAlgorithms) UnmarshalData(data []byte) error {
	schemes, err := unmarshalUint16List(data)
	if err == nil {
		s.Schemes = schemes
	}

	return err
}

// CertificateSignatureAlgorithms is the signature_algorithms_cert payload.
type CertificateSignatureAlgorithms struct {
	Schemes []uint16
}

func (CertificateSignatureAlgorithms) ExtensionType() Type { return TypeSignatureAlgorithmsCert }
func (s CertificateSignatureAlgorithms) MarshalData() ([]byte, error) {
	return marshalUint16List(s.Schemes)
}

func (s *CertificateSignatureAlgorithms) UnmarshalData(data []byte) error {
	schemes, err := unmarshalUint16List(data)
	if err == nil {
		s.Schemes = schemes
	}

	return err
}

func marshalUint16List(values []uint16) ([]byte, error) {
	if len(values) == 0 || len(values) > 0x7fff {
		return nil, dtlserrors.ErrLengthMismatch
	}
	out := make([]byte, 2, 2+(len(values)*2))
	binary.BigEndian.PutUint16(out, uint16(len(values)*2)) //nolint:gosec // count is bounded above.
	for _, value := range values {
		out = binary.BigEndian.AppendUint16(out, value)
	}

	return out, nil
}

func unmarshalUint16List(data []byte) ([]uint16, error) {
	if len(data) < 4 || int(binary.BigEndian.Uint16(data)) != len(data)-2 || (len(data)-2)%2 != 0 {
		return nil, dtlserrors.ErrLengthMismatch
	}
	values := make([]uint16, 0, (len(data)-2)/2)
	for offset := 2; offset < len(data); offset += 2 {
		values = append(values, binary.BigEndian.Uint16(data[offset:]))
	}

	return values, nil
}

func requireEmptyPayload(data []byte) error {
	if len(data) != 0 {
		return dtlserrors.ErrLengthMismatch
	}

	return nil
}
