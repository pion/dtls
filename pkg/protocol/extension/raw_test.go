// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRawListRoundTrip(t *testing.T) {
	wire := []byte{
		0x00, 0x11,
		0xfa, 0xce, 0x00, 0x03, 0x01, 0x02, 0x03,
		0xfa, 0xce, 0x00, 0x00,
		0x00, 0x10, 0x00, 0x02, 0xaa, 0xbb,
	}

	values, err := ParseList(wire)
	require.NoError(t, err)
	require.Len(t, values, 3)
	assert.Equal(t, Type(0xface), values[0].Type)
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, values[0].Data)
	assert.Equal(t, Type(0xface), values[1].Type, "duplicates must be preserved")

	encoded, err := MarshalRawList(values)
	require.NoError(t, err)
	assert.Equal(t, wire, encoded)
}

func TestParseListCopiesPayload(t *testing.T) {
	wire := []byte{0x00, 0x05, 0x12, 0x34, 0x00, 0x01, 0xaa}
	values, err := ParseList(wire)
	require.NoError(t, err)

	wire[6] = 0xbb
	assert.Equal(t, []byte{0xaa}, values[0].Data)
}

func TestParseListErrors(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
		err  error
	}{
		{name: "missing list length", wire: []byte{0x00}, err: dtlserrors.ErrBufferTooSmall},
		{name: "outer length", wire: []byte{0x00, 0x01}, err: dtlserrors.ErrLengthMismatch},
		{name: "short header", wire: []byte{0x00, 0x01, 0x00}, err: dtlserrors.ErrBufferTooSmall},
		{name: "short payload", wire: []byte{0x00, 0x04, 0x00, 0x01, 0x00, 0x01}, err: dtlserrors.ErrLengthMismatch},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseList(test.wire)
			assert.ErrorIs(t, err, test.err)
		})
	}
}

func TestMarshalListBounds(t *testing.T) {
	_, err := MarshalList([]Value{Raw{Type: 1, Data: make([]byte, 0x10000)}})
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidExtensionsLength)

	_, err = MarshalList([]Value{Raw{Type: 1, Data: make([]byte, 0xffff)}})
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidExtensionsLength)
}

func TestMarshalListRejectsNilExtension(t *testing.T) {
	_, err := MarshalList([]Value{nil})
	assert.ErrorIs(t, err, dtlserrors.ErrNilExtension)
}

func TestMarshalListTo(t *testing.T) {
	values := []Value{
		Raw{Type: 0xface, Data: []byte{0x01, 0x02, 0x03}},
		Raw{Type: TypeALPN, Data: []byte{0xaa}},
	}
	want, err := MarshalList(values)
	require.NoError(t, err)
	assert.Equal(t, len(want), MarshalListSize(values))

	out := make([]byte, MarshalListSize(values))
	n, err := MarshalListTo(out, values)
	require.NoError(t, err)
	assert.Equal(t, len(want), n)
	assert.Equal(t, want, out)
}

func TestMarshalListToErrors(t *testing.T) {
	_, err := MarshalListTo([]byte{0x00}, nil)
	assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)

	_, err = MarshalListTo(make([]byte, 2), []Value{nil})
	assert.ErrorIs(t, err, dtlserrors.ErrNilExtension)

	values := []Value{Raw{Type: 1, Data: []byte{0x01}}}
	_, err = MarshalListTo(make([]byte, MarshalListSize(values)-1), values)
	assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall)

	_, err = MarshalListTo(make([]byte, 2), []Value{Raw{Type: 1, Data: make([]byte, 0x10000)}})
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidExtensionsLength)
}

type mismatchedValue struct {
	size int
	data []byte
}

func (m mismatchedValue) ExtensionType() Type { return TypePadding }
func (m mismatchedValue) MarshalSize() int    { return m.size }
func (m mismatchedValue) MarshalData() ([]byte, error) {
	return m.data, nil
}

func TestMarshalListRejectsMismatchedPayloadSize(t *testing.T) {
	for _, test := range []struct {
		name  string
		value Value
	}{
		{name: "underreported data", value: mismatchedValue{size: 1}},
		{name: "overreported data", value: mismatchedValue{size: 0, data: []byte{0}}},
		{name: "negative size", value: mismatchedValue{size: -1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := MarshalList([]Value{test.value})
			assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)

			out := make([]byte, 16)
			n, err := MarshalListTo(out, []Value{test.value})
			assert.Equal(t, 2, n)
			assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
		})
	}
}

func FuzzParseList(f *testing.F) {
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0x04, 0xfa, 0xce, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, wire []byte) {
		values, err := ParseList(wire)
		if err != nil {
			return
		}

		encoded, err := MarshalRawList(values)
		require.NoError(t, err)
		assert.Equal(t, wire, encoded)
	})
}
