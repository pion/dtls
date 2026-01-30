// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"testing"
	"time"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
)

func TestRandomConnectionIDGenerator(t *testing.T) {
	cases := map[string]struct {
		reason string
		size   int
	}{
		"LengthMatch": {
			reason: "Zero size should match length of generated CID.",
			size:   0,
		},
		"LengthMatchSome": {
			reason: "Non-zero size should match length of generated CID with non-zero.",
			size:   8,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.size, len(RandomCIDGenerator(tc.size)()), "%s\nRandomCIDGenerator mismatch", tc.reason)
		})
	}
}

func TestOnlySendCIDGenerator(t *testing.T) {
	cases := map[string]struct {
		reason string
	}{
		"LengthMatch": {
			reason: "CID length should always be zero.",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equalf(t, 0, len(OnlySendCIDGenerator()()), "%s\nOnlySendCIDGenerator mismatch", tc.reason)
		})
	}
}

func TestCIDDatagramRouter(t *testing.T) {
	cid := []byte("abcd1234")
	cidLen := 8
	appRecord, err := (&recordlayer.RecordLayer{
		Header: recordlayer.Header{
			Epoch:   1,
			Version: protocol.Version1_2,
		},
		Content: &protocol.ApplicationData{
			Data: []byte("application data"),
		},
	}).Marshal()
	assert.NoError(t, err)

	appData, err := (&protocol.ApplicationData{
		Data: []byte("some data"),
	}).Marshal()
	assert.NoError(t, err)

	inner, err := (&recordlayer.InnerPlaintext{
		Content:  appData,
		RealType: protocol.ContentTypeApplicationData,
	}).Marshal()
	assert.NoError(t, err)

	cidHeader, err := (&recordlayer.Header{
		Epoch:          1,
		Version:        protocol.Version1_2,
		ContentType:    protocol.ContentTypeConnectionID,
		ContentLen:     uint16(len(inner)), //nolint:gosec // G115
		ConnectionID:   cid,
		SequenceNumber: 1,
	}).Marshal()
	assert.NoError(t, err)

	cases := map[string]struct {
		reason   string
		size     int
		datagram []byte
		ok       bool
		want     string
	}{
		"EmptyDatagram": {
			reason:   "If datagram is empty, we cannot extract an identifier",
			size:     cidLen,
			datagram: []byte{},
			ok:       false,
			want:     "",
		},
		"NotADTLSRecord": {
			reason:   "If datagram is not a DTLS record, we cannot extract an identifier",
			size:     cidLen,
			datagram: []byte("not a DTLS record"),
			ok:       false,
			want:     "",
		},
		"NotAConnectionIDDatagram": {
			reason:   "If datagram does not contain any Connection ID records, we cannot extract an identifier",
			size:     cidLen,
			datagram: appRecord,
			ok:       false,
			want:     "",
		},
		"OneRecordConnectionID": {
			reason:   "If datagram contains one Connection ID record, we should be able to extract it.",
			size:     cidLen,
			datagram: append(cidHeader, inner...),
			ok:       true,
			want:     string(cid),
		},
		"OneRecordConnectionIDAltLength": {
			//nolint:lll
			reason: "If datagram contains one Connection ID record, but it has the wrong length we should not be able to extract it.",
			size:   cidLen,
			datagram: func() []byte {
				altCIDHeader, err := (&recordlayer.Header{
					Epoch:          1,
					Version:        protocol.Version1_2,
					ContentType:    protocol.ContentTypeConnectionID,
					ContentLen:     uint16(len(inner)), //nolint:gosec // G115
					ConnectionID:   []byte("abcd"),
					SequenceNumber: 1,
				}).Marshal()
				assert.NoError(t, err)

				return append(altCIDHeader, inner...)
			}(),
			ok:   false,
			want: "",
		},
		"MultipleRecordOneConnectionID": {
			//nolint:lll
			reason:   "If datagram contains multiple records and one is a Connection ID record, we should be able to extract it.",
			size:     8,
			datagram: append(append(appRecord, cidHeader...), inner...),
			ok:       true,
			want:     string(cid),
		},
		"MultipleRecordMultipleConnectionID": {
			//nolint:lll
			reason: "If datagram contains multiple records and multiple are Connection ID records, we should extract the first one.",
			size:   8,
			datagram: append(append(append(appRecord, func() []byte {
				altCIDHeader, err := (&recordlayer.Header{
					Epoch:          1,
					Version:        protocol.Version1_2,
					ContentType:    protocol.ContentTypeConnectionID,
					ContentLen:     uint16(len(inner)), //nolint:gosec // G115
					ConnectionID:   []byte("1234abcd"),
					SequenceNumber: 1,
				}).Marshal()
				assert.NoError(t, err)

				return append(altCIDHeader, inner...)
			}()...), cidHeader...), inner...),
			ok:   true,
			want: "1234abcd",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cid, ok := cidDatagramRouter(tc.size)(tc.datagram)
			assert.Equal(t, tc.ok, ok, "%s\ncidDatagramRouter mismatch", tc.reason)
			assert.Equal(t, tc.want, cid, "%s\ncidDatagramRouter mismatch", tc.reason)
		})
	}
}

func TestCIDConnIdentifier(t *testing.T) {
	cid := []byte("abcd1234")
	cs := uint16(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	sh, err := (&recordlayer.RecordLayer{
		Header: recordlayer.Header{
			Epoch:   0,
			Version: protocol.Version1_2,
		},
		Content: &handshake.Handshake{
			Message: &handshake.MessageServerHello{
				Version:           protocol.Version1_2,
				Random:            handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: [28]byte{}},
				SessionID:         []byte("hello"),
				CipherSuiteID:     &cs,
				CompressionMethod: defaultCompressionMethods()[0],
				Extensions: []extension.Extension{
					&extension.ConnectionID{
						CID: cid,
					},
				},
			},
		},
	}).Marshal()
	assert.NoError(t, err)

	appRecord, err := (&recordlayer.RecordLayer{
		Header: recordlayer.Header{
			Epoch:   1,
			Version: protocol.Version1_2,
		},
		Content: &protocol.ApplicationData{
			Data: []byte("application data"),
		},
	}).Marshal()
	assert.NoError(t, err)

	cases := map[string]struct {
		reason   string
		datagram []byte
		ok       bool
		want     string
	}{
		"EmptyDatagram": {
			reason:   "If datagram is empty, we cannot extract an identifier",
			datagram: []byte{},
			ok:       false,
			want:     "",
		},
		"NotADTLSRecord": {
			reason:   "If datagram is not a DTLS record, we cannot extract an identifier",
			datagram: []byte("not a DTLS record"),
			ok:       false,
			want:     "",
		},
		"NotAServerhelloDatagram": {
			reason:   "If datagram does not contain any ServerHello record, we cannot extract an identifier",
			datagram: appRecord,
			ok:       false,
			want:     "",
		},
		"OneRecordServerHello": {
			reason:   "If datagram contains one ServerHello record, we should be able to extract an identifier.",
			datagram: sh,
			ok:       true,
			want:     string(cid),
		},
		"MultipleRecordFirstServerHello": {
			//nolint:lll
			reason:   "If datagram contains multiple records and the first is a ServerHello record, we should be able to extract an identifier.",
			datagram: append(sh, appRecord...),
			ok:       true,
			want:     string(cid),
		},
		"MultipleRecordNotFirstServerHello": {
			//nolint:lll
			reason:   "If datagram contains multiple records and the first is not a ServerHello record, we should not be able to extract an identifier.",
			datagram: append(appRecord, sh...),
			ok:       false,
			want:     "",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cid, ok := cidConnIdentifier()(tc.datagram)
			assert.Equalf(t, tc.ok, ok, "%s\ncidConnIdentifier mismatch", tc.reason)
			assert.Equalf(t, tc.want, cid, "%s\ncidConnIdentifier mismatch", tc.reason)
		})
	}
}
