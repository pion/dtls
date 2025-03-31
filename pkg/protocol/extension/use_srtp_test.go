// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtensionUseSRTP(t *testing.T) {
	t.Run("No MasterKeyIdentifier", func(t *testing.T) {
		rawUseSRTP := []byte{0x00, 0x0e, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00}
		parsedUseSRTP := &UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			MasterKeyIdentifier: []byte{},
		}

		marshaled, err := parsedUseSRTP.Marshal()
		assert.NoError(t, err)
		assert.Equal(t, rawUseSRTP, marshaled)

		unmarshaled := &UseSRTP{}
		assert.NoError(t, unmarshaled.Unmarshal(rawUseSRTP))
		assert.Equal(t, parsedUseSRTP, unmarshaled)
	})

	t.Run("With MasterKeyIdentifier", func(t *testing.T) {
		rawUseSRTP := []byte{0x00, 0x0e, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x05, 0xA, 0xB, 0xC, 0xD, 0xE}
		parsedUseSRTP := &UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			MasterKeyIdentifier: []byte{0xA, 0xB, 0xC, 0xD, 0xE},
		}

		marshaled, err := parsedUseSRTP.Marshal()
		assert.NoError(t, err)
		assert.Equal(t, rawUseSRTP, marshaled)

		unmarshaled := &UseSRTP{}
		assert.NoError(t, unmarshaled.Unmarshal(rawUseSRTP))
		assert.Equal(t, parsedUseSRTP, unmarshaled)
	})

	t.Run("Invalid Lengths", func(t *testing.T) {
		unmarshaled := &UseSRTP{}

		err := unmarshaled.Unmarshal([]byte{0x00, 0x0e, 0x00, 0x05, 0x00, 0x04, 0x00, 0x01, 0x00})
		assert.ErrorIs(t, err, errLengthMismatch)

		err = unmarshaled.Unmarshal([]byte{0x00, 0x0e, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x01})
		assert.ErrorIs(t, err, errLengthMismatch)

		_, err = (&UseSRTP{
			ProtectionProfiles:  []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			MasterKeyIdentifier: make([]byte, 500),
		}).Marshal()
		assert.ErrorIs(t, err, errMasterKeyIdentifierTooLarge)
	})
}
