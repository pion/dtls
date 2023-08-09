// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package util

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func TestAddUint48(t *testing.T) {
	cases := map[string]struct {
		reason  string
		builder *cryptobyte.Builder
		postAdd func(*cryptobyte.Builder)
		in      uint64
		want    []byte
	}{
		"OnlyUint48": {
			reason:  "Adding only a 48-bit unsigned integer should yield expected result.",
			builder: &cryptobyte.Builder{},
			in:      0xfefcff3cfdfc,
			want:    []byte{254, 252, 255, 60, 253, 252},
		},
		"ExistingAddUint48": {
			reason: "Adding a 48-bit unsigned integer to a builder with existing bytes should yield expected result.",
			builder: func() *cryptobyte.Builder {
				var b cryptobyte.Builder
				b.AddUint64(0xffffffffffffffff)
				return &b
			}(),
			in:   0xfefcff3cfdfc,
			want: []byte{255, 255, 255, 255, 255, 255, 255, 255, 254, 252, 255, 60, 253, 252},
		},
		"ExistingAddUint48AndMore": {
			reason: "Adding a 48-bit unsigned integer to a builder with existing bytes, then adding more bytes, should yield expected result.",
			builder: func() *cryptobyte.Builder {
				var b cryptobyte.Builder
				b.AddUint64(0xffffffffffffffff)
				return &b
			}(),
			postAdd: func(b *cryptobyte.Builder) {
				b.AddUint32(0xffffffff)
			},
			in:   0xfefcff3cfdfc,
			want: []byte{255, 255, 255, 255, 255, 255, 255, 255, 254, 252, 255, 60, 253, 252, 255, 255, 255, 255},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			AddUint48(tc.builder, tc.in)
			if tc.postAdd != nil {
				tc.postAdd(tc.builder)
			}
			got := tc.builder.BytesOrPanic()
			if !bytes.Equal(got, tc.want) {
				t.Errorf("Bytes() = %v, want %v", got, tc.want)
			}
		})
	}
}
