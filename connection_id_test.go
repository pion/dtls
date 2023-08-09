// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import "testing"

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
			if cidLen := len(RandomCIDGenerator(tc.size)()); cidLen != tc.size {
				t.Errorf("%s\nRandomCIDGenerator: expected CID length %d, but got %d.", tc.reason, tc.size, cidLen)
			}
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
			if cidLen := len(OnlySendCIDGenerator()()); cidLen != 0 {
				t.Errorf("%s\nOnlySendCIDGenerator: expected CID length %d, but got %d.", tc.reason, 0, cidLen)
			}
		})
	}
}
