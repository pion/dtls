// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension_test

import (
	"encoding/binary"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls12"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/stretchr/testify/require"
)

type payloadValue interface {
	extension.Value
	extension.PayloadUnmarshaller
}

func payloadFromWire(wire []byte, typ extension.Type) ([]byte, bool) {
	if len(wire) > 0xffff {
		return nil, false
	}

	list := make([]byte, 2, 2+len(wire))
	binary.BigEndian.PutUint16(list, uint16(len(wire))) //nolint:gosec // length is bounded above.
	list = append(list, wire...)
	raw, err := extension.ParseList(list)
	if err != nil || len(raw) != 1 || raw[0].Type != typ {
		return nil, false
	}

	return raw[0].Data, true
}

func fuzzWirePayload(
	f *testing.F,
	typ extension.Type,
	newValue func() payloadValue,
	seeds ...[]byte,
) {
	f.Helper()

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, wire []byte) {
		payload, ok := payloadFromWire(wire, typ)
		if !ok {
			return
		}

		value := newValue()
		if err := value.UnmarshalData(payload); err != nil {
			return
		}
		_, err := value.MarshalData()
		require.NoError(t, err, "MarshalData after successful UnmarshalData")
	})
}

// FuzzALPNUnmarshal exercises the ClientHello ALPN payload from a complete
// extension record.
func FuzzALPNUnmarshal(f *testing.F) {
	fuzzWirePayload(f, extension.TypeALPN, func() payloadValue { return &extension.ALPNOffer{} },
		[]byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'},
		[]byte{0x00, 0x10, 0x00, 0x02, 0x00, 0x00},
	)
}

// FuzzCertificateAuthUnmarshal exercises certificate_authorities payloads.
func FuzzCertificateAuthUnmarshal(f *testing.F) {
	fuzzWirePayload(f, extension.TypeCertificateAuthorities, func() payloadValue {
		return &extension13.CertificateAuthorities{}
	},
		[]byte{0x00, 0x2f, 0x00, 0x07, 0x00, 0x05, 0x00, 0x03, 'c', 'a', '1'},
		[]byte{0x00, 0x2f, 0x00, 0x02, 0x00, 0x00},
	)
}

// FuzzCookieExtUnmarshal exercises cookie payloads.
func FuzzCookieExtUnmarshal(f *testing.F) {
	fuzzWirePayload(f, extension.TypeCookie, func() payloadValue { return &extension13.Cookie{} },
		[]byte{0x00, 0x2c, 0x00, 0x04, 0x00, 0x02, 0x01, 0x42},
		[]byte{0x00, 0x2c, 0x00, 0x02, 0x00, 0x00},
	)
}

// FuzzExtensionSupportedGroupsUnmarshal exercises supported_groups payloads.
func FuzzExtensionSupportedGroupsUnmarshal(f *testing.F) {
	fuzzWirePayload(f, extension.TypeSupportedGroups, func() payloadValue { return &extension.SupportedGroups{} },
		[]byte{0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d},
		[]byte{0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0xfa, 0xfa},
	)
}

// FuzzExtensionSupportedPointFormatsUnmarshal exercises ec_point_formats payloads.
func FuzzExtensionSupportedPointFormatsUnmarshal(f *testing.F) {
	fuzzWirePayload(f, extension.TypeSupportedPointFormats, func() payloadValue {
		return &extension12.SupportedPointFormats{}
	},
		[]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00},
		[]byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0xff},
	)
}

// FuzzExtensionUseSRTPUnmarshal exercises use_srtp payloads.
func FuzzExtensionUseSRTPUnmarshal(f *testing.F) {
	fuzzWirePayload(f, extension.TypeUseSRTP, func() payloadValue { return &extension.SRTPOffer{} },
		[]byte{0x00, 0x0e, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00},
		[]byte{0x00, 0x0e, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x01, 0x05, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e},
	)
}

// FuzzPskKeyExchangeModesUnmarshal exercises psk_key_exchange_modes payloads.
func FuzzPskKeyExchangeModesUnmarshal(f *testing.F) {
	fuzzWirePayload(f, extension.TypePSKKeyExchangeModes, func() payloadValue {
		return &extension13.PSKKeyExchangeModes{}
	},
		[]byte{0x00, 0x2d, 0x00, 0x02, 0x01, 0x00},
		[]byte{0x00, 0x2d, 0x00, 0x01, 0x00},
	)
}

// FuzzRenegotiationInfoUnmarshal exercises renegotiation_info payloads.
func FuzzRenegotiationInfoUnmarshal(f *testing.F) {
	fuzzWirePayload(f, extension.TypeRenegotiationInfo, func() payloadValue {
		return &extension12.RenegotiationInfo{}
	},
		[]byte{0xff, 0x01, 0x00, 0x01, 0x00},
		[]byte{0xff, 0x01, 0x00, 0x03, 0x00, 0xde, 0xad},
	)
}

// FuzzServerNameUnmarshal exercises ClientHello server_name payloads.
func FuzzServerNameUnmarshal(f *testing.F) {
	fuzzWirePayload(f, extension.TypeServerName, func() payloadValue { return &extension.ServerNameOffer{} },
		[]byte{0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 't', 'e', 's', 't', '.', 'd', 'o', 'm', 'a', 'i', 'n'},
		[]byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00},
	)
}
