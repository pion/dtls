// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

const (
	useSRTPHeaderSize = 6
	maxUint16         = (1 << 16) - 1
)

// UseSRTP allows a Client/Server to negotiate what SRTPProtectionProfiles
// they both support
//
// https://datatracker.ietf.org/doc/html/rfc5764
type UseSRTP struct {
	ProtectionProfiles  []SRTPProtectionProfile
	MasterKeyIdentifier []byte
}

// TypeValue returns the extension TypeValue.
func (u UseSRTP) TypeValue() TypeValue {
	return UseSRTPTypeValue
}

// Marshal encodes the extension.
func (u *UseSRTP) Marshal() ([]byte, error) {
	if len(u.MasterKeyIdentifier) > 255 {
		return nil, dtlserrors.ErrMasterKeyIdentifierTooLarge
	}

	extensionDataLen := 2 + (len(u.ProtectionProfiles) * 2) + 1 + len(u.MasterKeyIdentifier)
	if extensionDataLen > maxUint16 {
		return nil, dtlserrors.ErrUseSRTPDataTooLarge
	}
	out := make([]byte, 4+extensionDataLen)

	binary.BigEndian.PutUint16(out, uint16(u.TypeValue()))
	//nolint:gosec // G115
	binary.BigEndian.PutUint16(
		out[2:],
		uint16(extensionDataLen),
	)
	binary.BigEndian.PutUint16(out[4:], uint16(len(u.ProtectionProfiles)*2)) //nolint:gosec // G115

	offset := useSRTPHeaderSize
	for _, v := range u.ProtectionProfiles {
		binary.BigEndian.PutUint16(out[offset:], uint16(v))
		offset += 2
	}

	//nolint:gosec // G115: MKI length is validated to be <= 255 above.
	out[offset] = byte(len(u.MasterKeyIdentifier))
	copy(out[offset+1:], u.MasterKeyIdentifier)

	return out, nil
}

// Unmarshal populates the extension from encoded data.
func (u *UseSRTP) Unmarshal(data []byte) error {
	payload, err := extensionPayload(data, u.TypeValue())
	if err != nil {
		return err
	}

	return u.unmarshalPayload(payload)
}

func (u *UseSRTP) unmarshalPayload(data []byte) error {
	if len(data) < 3 {
		return dtlserrors.ErrBufferTooSmall
	}

	profilesLength := int(binary.BigEndian.Uint16(data))
	masterKeyIdentifierIndex := 2 + profilesLength
	if profilesLength%2 != 0 || masterKeyIdentifierIndex+1 > len(data) {
		return dtlserrors.ErrLengthMismatch
	}

	masterKeyIdentifierLen := int(data[masterKeyIdentifierIndex])
	masterKeyIdentifierEnd := masterKeyIdentifierIndex + 1 + masterKeyIdentifierLen
	if masterKeyIdentifierEnd != len(data) {
		return dtlserrors.ErrLengthMismatch
	}

	profileCount := profilesLength / 2
	for i := range profileCount {
		supportedProfile := SRTPProtectionProfile(binary.BigEndian.Uint16(data[2+(i*2):]))
		if _, ok := srtpProtectionProfiles()[supportedProfile]; ok {
			u.ProtectionProfiles = append(u.ProtectionProfiles, supportedProfile)
		}
	}

	u.MasterKeyIdentifier = append(
		[]byte{},
		data[masterKeyIdentifierIndex+1:masterKeyIdentifierEnd]...,
	)

	return nil
}
