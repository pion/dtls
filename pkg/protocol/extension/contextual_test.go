// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContextualPayloads(t *testing.T) {
	tests := []struct {
		name  string
		value Value
		out   interface {
			Value
			PayloadUnmarshaller
		}
	}{
		{name: "server name offer", value: ServerNameOffer{ServerName: "example.com"}, out: &ServerNameOffer{}},
		{name: "server name ack", value: ServerNameAck{}, out: &ServerNameAck{}},
		{name: "alpn offer", value: ALPNOffer{Protocols: []string{"h2", "http/1.1"}}, out: &ALPNOffer{}},
		{name: "alpn selection", value: ALPNSelection{Protocol: "h2"}, out: &ALPNSelection{}},
		{
			name: "srtp offer",
			value: SRTPOffer{
				ProtectionProfiles:  []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80, SRTP_AEAD_AES_128_GCM},
				MasterKeyIdentifier: []byte{1, 2},
			},
			out: &SRTPOffer{},
		},
		{
			name: "srtp selection",
			value: SRTPSelection{
				ProtectionProfile:   SRTP_AES128_CM_HMAC_SHA1_80,
				MasterKeyIdentifier: []byte{3},
			},
			out: &SRTPSelection{},
		},
		{
			name:  "supported groups preserve unknown",
			value: SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519, elliptic.Curve(0xfafa)}},
			out:   &SupportedGroups{},
		},
		{
			name:  "signature algorithms preserve unknown",
			value: SignatureAlgorithms{Schemes: []uint16{0x0403, 0xfafa}},
			out:   &SignatureAlgorithms{},
		},
		{
			name:  "certificate signature algorithms",
			value: CertificateSignatureAlgorithms{Schemes: []uint16{0x0804}},
			out:   &CertificateSignatureAlgorithms{},
		},
		{name: "connection id", value: ConnectionID{CID: []byte{4, 5, 6}}, out: &ConnectionID{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := test.value.MarshalData()
			require.NoError(t, err)
			assert.Equal(t, len(data), test.value.MarshalSize())
			require.NoError(t, test.out.UnmarshalData(data))

			roundTrip, err := test.out.MarshalData()
			require.NoError(t, err)
			assert.Equal(t, data, roundTrip)
			assert.Equal(t, len(roundTrip), test.out.MarshalSize())
		})
	}
}

func TestContextualFormValidation(t *testing.T) {
	assert.ErrorIs(t, (&ServerNameAck{}).UnmarshalData([]byte{0}), dtlserrors.ErrLengthMismatch)
	assert.ErrorIs(t, (&ServerNameOffer{}).UnmarshalData(nil), dtlserrors.ErrInvalidSNIFormat)
	assert.ErrorIs(t, (&ALPNSelection{}).UnmarshalData([]byte{0, 4, 1, 'a', 1, 'b'}), ErrALPNInvalidFormat)
	assert.ErrorIs(t, (&SRTPSelection{}).UnmarshalData([]byte{0, 4, 0, 1, 0, 2, 0}), dtlserrors.ErrLengthMismatch)
	assert.ErrorIs(t, (&SupportedGroups{}).UnmarshalData([]byte{0, 1, 0}), dtlserrors.ErrLengthMismatch)
}

func FuzzContextualPayloadUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = (&ServerNameOffer{}).UnmarshalData(data)
		_ = (&ServerNameAck{}).UnmarshalData(data)
		_ = (&ALPNOffer{}).UnmarshalData(data)
		_ = (&ALPNSelection{}).UnmarshalData(data)
		_ = (&SRTPOffer{}).UnmarshalData(data)
		_ = (&SRTPSelection{}).UnmarshalData(data)
		_ = (&SupportedGroups{}).UnmarshalData(data)
		_ = (&SignatureAlgorithms{}).UnmarshalData(data)
		_ = (&CertificateSignatureAlgorithms{}).UnmarshalData(data)
		_ = (&ConnectionID{}).UnmarshalData(data)
	})
}
