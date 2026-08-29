// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"testing"
	"time"

	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
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
	epochZeroRecord, err := marshalTestRecord(recordlayer.Header{Epoch: 0, Version: protocol.Version1_2}, &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify})
	assert.NoError(t, err)
	protectedWithoutCIDRecord, err := marshalTestRecord(recordlayer.Header{Epoch: 1, Version: protocol.Version1_2}, &protocol.ApplicationData{Data: []byte("application data")})
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
		"EmptyDatagram":            {reason: "If datagram is empty, we cannot extract an identifier", size: cidLen, datagram: []byte{}, ok: false, want: ""},
		"NotADTLSRecord":           {reason: "If datagram is not a DTLS record, we cannot extract an identifier", size: cidLen, datagram: []byte("not a DTLS record"), ok: false, want: ""},
		"NotAConnectionIDDatagram": {reason: "If datagram does not contain any Connection ID records, we cannot extract an identifier", size: cidLen, datagram: epochZeroRecord, ok: false, want: ""},
		"ProtectedRecordWithoutCIDPrefix": {
			reason: "A protected DTLS 1.2 record without type 25 is invalid after CID negotiation and must not route through a later CID.",
			size:   cidLen,
			datagram: append(
				append(append([]byte{}, protectedWithoutCIDRecord...), cidHeader...),
				inner...,
			),
			ok:   false,
			want: "",
		},
		"OneRecordConnectionID": {reason: "If datagram contains one Connection ID record, we should be able to extract it.", size: cidLen, datagram: append(cidHeader, inner...), ok: true, want: string(cid)},
		"OneRecordConnectionIDAltLength": {
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
			reason:   "An epoch-zero DTLS 1.2 record may precede a protected Connection ID record in the same datagram.",
			size:     8,
			datagram: append(append(epochZeroRecord, cidHeader...), inner...),
			ok:       true,
			want:     string(cid),
		},
		"MultipleRecordMultipleConnectionID": {
			reason: "If datagram contains multiple records and multiple are Connection ID records, we should extract the first one.",
			size:   8,
			datagram: append(append(append(epochZeroRecord, func() []byte {
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

func TestCIDDatagramRouter13(t *testing.T) {
	cid := []byte("abcd1234")
	plaintextPrefix, err := marshalTestRecord(recordlayer.Header{Version: protocol.Version1_2}, &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify})
	assert.NoError(t, err)

	makeRecord := func(t *testing.T, connectionID []byte, sequenceNumber uint16) []byte {
		t.Helper()

		record, err := (&recordlayer.CiphertextRecord{Header: recordlayer.UnifiedHeader{ConnectionID: connectionID, SequenceNumber: sequenceNumber}, EncryptedRecord: make([]byte, 16)}).Marshal()
		assert.NoError(t, err)

		return record
	}

	recordWithCID := makeRecord(t, cid, 1)
	recordWithoutCID := makeRecord(t, nil, 2)
	otherCID := []byte("1234abcd")
	recordWithOtherCID := makeRecord(t, otherCID, 3)

	cases := map[string]struct {
		reason   string
		size     int
		datagram []byte
		ok       bool
		want     string
	}{
		"OneRecordConnectionID": {reason: "A unified-header record with the C bit should expose its CID.", size: len(cid), datagram: recordWithCID, ok: true, want: string(cid)},
		"NoConnectionIDBit":     {reason: "A unified-header record without the C bit has no routing identifier.", size: len(cid), datagram: recordWithoutCID, ok: false},
		"WrongConfiguredLength": {reason: "A unified-header CID must have the listener's configured fixed length.", size: len(cid) - 1, datagram: recordWithCID, ok: false},
		"MultipleRecords":       {reason: "The first CID in a datagram containing unified-header records should be used.", size: len(cid), datagram: append(append([]byte{}, recordWithCID...), recordWithOtherCID...), ok: true, want: string(cid)},
		"FixedPrefix":           {reason: "A CID in a unified-header record should route after a fixed-header CID-less prefix.", size: len(cid), datagram: append(append([]byte{}, plaintextPrefix...), recordWithCID...), ok: true, want: string(cid)},
		"MalformedSuffix":       {reason: "A malformed suffix should not hide a CID in an already framed record.", size: len(cid), datagram: append(append([]byte{}, recordWithCID...), 0xff), ok: true, want: string(cid)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := cidDatagramRouter(tc.size)(tc.datagram)
			assert.Equal(t, tc.ok, ok, "%s\ncidDatagramRouter mismatch", tc.reason)
			assert.Equal(t, tc.want, got, "%s\ncidDatagramRouter mismatch", tc.reason)
		})
	}
}

func TestCIDConnIdentifier(t *testing.T) {
	cid := []byte("abcd1234")
	cs := uint16(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	sh, err := marshalTestRecord(recordlayer.Header{
		Epoch:   0,
		Version: protocol.Version1_2,
	}, &handshake.Handshake{
		Message: &handshake.MessageServerHello{
			Version:           protocol.Version1_2,
			Random:            handshake.Random{GMTUnixTime: time.Unix(500, 0), RandomBytes: [28]byte{}},
			SessionID:         []byte("hello"),
			CipherSuiteID:     &cs,
			CompressionMethod: dtlsflight.DefaultCompressionMethods()[0],
			Extensions: []extension.Value{
				&extension.ConnectionID{CID: cid},
			},
		},
	})
	assert.NoError(t, err)

	appRecord, err := marshalTestRecord(recordlayer.Header{Epoch: 1, Version: protocol.Version1_2}, &protocol.ApplicationData{Data: []byte("application data")})
	assert.NoError(t, err)
	dtls13Ciphertext, err := (&recordlayer.CiphertextRecord{Header: recordlayer.UnifiedHeader{SequenceNumber: 1}, EncryptedRecord: make([]byte, 16)}).Marshal()
	assert.NoError(t, err)

	cases := map[string]struct {
		reason   string
		datagram []byte
		ok       bool
		want     string
	}{
		"EmptyDatagram":           {reason: "If datagram is empty, we cannot extract an identifier", datagram: []byte{}, ok: false, want: ""},
		"NotADTLSRecord":          {reason: "If datagram is not a DTLS record, we cannot extract an identifier", datagram: []byte("not a DTLS record"), ok: false, want: ""},
		"NotAServerhelloDatagram": {reason: "If datagram does not contain any ServerHello record, we cannot extract an identifier", datagram: appRecord, ok: false, want: ""},
		"OneRecordServerHello":    {reason: "If datagram contains one ServerHello record, we should be able to extract an identifier.", datagram: sh, ok: true, want: string(cid)},
		"MultipleRecordFirstServerHello": {
			reason:   "If datagram contains multiple records and the first is a ServerHello record, we should be able to extract an identifier.",
			datagram: append(sh, appRecord...),
			ok:       true,
			want:     string(cid),
		},
		"DTLS13ServerFlight": {
			reason:   "A ServerHello followed by DTLS 1.3 unified-header records should register its Connection ID.",
			datagram: append(append([]byte{}, sh...), dtls13Ciphertext...),
			ok:       true,
			want:     string(cid),
		},
		"MultipleRecordNotFirstServerHello": {
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
