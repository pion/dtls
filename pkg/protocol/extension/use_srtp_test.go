// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"errors"
	"reflect"
	"testing"
)

func TestExtensionUseSRTP(t *testing.T) {
	t.Run("No MasterKeyIdentifier", func(t *testing.T) {
		rawUseSRTP := []byte{0x00, 0x0e, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00}
		parsedUseSRTP := &UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			MasterKeyIdentifier: []byte{},
		}

		marshaled, err := parsedUseSRTP.Marshal()
		if err != nil {
			t.Error(err)
		} else if !reflect.DeepEqual(marshaled, rawUseSRTP) {
			t.Errorf("extensionUseSRTP marshal: got %#v, want %#v", marshaled, rawUseSRTP)
		}

		unmarshaled := &UseSRTP{}
		if err := unmarshaled.Unmarshal(rawUseSRTP); err != nil {
			t.Error(err)
		} else if !reflect.DeepEqual(unmarshaled, parsedUseSRTP) {
			t.Errorf("extensionUseSRTP unmarshal: got %#v, want %#v", unmarshaled, parsedUseSRTP)
		}
	})

	t.Run("With MasterKeyIdentifier", func(t *testing.T) {
		rawUseSRTP := []byte{0x00, 0x0e, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x05, 0xA, 0xB, 0xC, 0xD, 0xE}
		parsedUseSRTP := &UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			MasterKeyIdentifier: []byte{0xA, 0xB, 0xC, 0xD, 0xE},
		}

		marshaled, err := parsedUseSRTP.Marshal()
		if err != nil {
			t.Error(err)
		} else if !reflect.DeepEqual(marshaled, rawUseSRTP) {
			t.Errorf("extensionUseSRTP marshal: got %#v, want %#v", marshaled, rawUseSRTP)
		}

		unmarshaled := &UseSRTP{}
		if err := unmarshaled.Unmarshal(rawUseSRTP); err != nil {
			t.Error(err)
		} else if !reflect.DeepEqual(unmarshaled, parsedUseSRTP) {
			t.Errorf("extensionUseSRTP unmarshal: got %#v, want %#v", unmarshaled, parsedUseSRTP)
		}
	})

	t.Run("Invalid Lengths", func(t *testing.T) {
		unmarshaled := &UseSRTP{}

		if err := unmarshaled.Unmarshal([]byte{0x00, 0x0e, 0x00, 0x05, 0x00, 0x04, 0x00, 0x01, 0x00}); !errors.Is(errLengthMismatch, err) {
			t.Error(err)
		}

		if err := unmarshaled.Unmarshal([]byte{0x00, 0x0e, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x01}); !errors.Is(errLengthMismatch, err) {
			t.Error(err)
		}

		if _, err := (&UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			MasterKeyIdentifier: make([]byte, 500),
		}).Marshal(); !errors.Is(errMasterKeyIdentifierTooLarge, err) {
			panic(err)
		}
	})
}
