// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ciphersuite provides the crypto operations needed for a DTLS CipherSuite
package ciphersuite

import (
	"bytes"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func TestGenerateAEADAdditionalDataCID(t *testing.T) {
	cases := map[string]struct {
		reason     string
		header     *recordlayer.Header
		payloadLen int
		expected   []byte
	}{
		"WithConnectionID": {
			reason: "Should successfully generate additional data with valid header",
			header: &recordlayer.Header{
				ContentType:    protocol.ContentTypeConnectionID,
				ConnectionID:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
				Version:        protocol.Version1_2,
				Epoch:          2,
				SequenceNumber: 277,
			},
			payloadLen: 1784,
			expected: []byte{
				255, 255, 255, 255, 255, 255, 255, 255, 25, 8, 25, 254, 253,
				0, 2, 0, 0, 0, 0, 1, 21, 1, 2, 3, 4, 5, 6, 7, 8, 6, 248,
			},
		},
		"IgnoreContentType": {
			reason: "Should use Connection ID content type regardless of header content type.",
			header: &recordlayer.Header{
				ContentType:    protocol.ContentTypeAlert,
				ConnectionID:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
				Version:        protocol.Version1_2,
				Epoch:          2,
				SequenceNumber: 277,
			},
			payloadLen: 1784,
			expected: []byte{
				255, 255, 255, 255, 255, 255, 255, 255, 25, 8, 25, 254, 253,
				0, 2, 0, 0, 0, 0, 1, 21, 1, 2, 3, 4, 5, 6, 7, 8, 6, 248,
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			data := generateAEADAdditionalDataCID(tc.header, tc.payloadLen)
			if !bytes.Equal(data, tc.expected) {
				t.Errorf("%s\nUnexpected additional data\nwant: %v\ngot: %v", tc.reason, tc.expected, data)
			}
		})
	}
}
