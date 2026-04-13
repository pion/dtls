// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOIDFilters(t *testing.T) {
	oid := []byte{0x55, 0x04, 0x03}
	values := []byte{0xde, 0xad, 0xbe, 0xef}
	filter := OIDFilter{OID: oid, Values: values}
	extension := OIDFilters{Filters: []OIDFilter{filter}}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x30, // extension type (48)
		0x00, 0x0c, // extension data length
		0x00, 0x0a, // filter list length
		0x03,             // OID length
		0x55, 0x04, 0x03, // OID bytes (id-at-commonName)
		0x00, 0x04, // values length
		0xde, 0xad, 0xbe, 0xef, // values bytes
	}
	assert.Equal(t, expect, raw)

	newExtension := OIDFilters{}
	assert.NoError(t, newExtension.Unmarshal(expect))
	assert.Len(t, newExtension.Filters, 1)
	assert.Equal(t, oid, newExtension.Filters[0].OID)
	assert.Equal(t, values, newExtension.Filters[0].Values)
}

func TestOIDFilters_MultipleFilters(t *testing.T) {
	oid1 := []byte{0x55, 0x04}
	values1 := []byte{0xaa, 0xbb}
	oid2 := []byte{0x55, 0x05}
	values2 := []byte{0x01, 0x02, 0x03, 0x04}
	extension := OIDFilters{Filters: []OIDFilter{
		{OID: oid1, Values: values1},
		{OID: oid2, Values: values2},
	}}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x30, // extension type
		0x00, 0x12, // extension data length
		0x00, 0x10, // filter list length
		0x02,       // OID length
		0x55, 0x04, // OID bytes
		0x00, 0x02, // values length
		0xaa, 0xbb, // values bytes
		0x02,       // OID length
		0x55, 0x05, // OID bytes
		0x00, 0x04, // values length
		0x01, 0x02, 0x03, 0x04, // values bytes
	}
	assert.Equal(t, expect, raw)

	newExtension := OIDFilters{}
	assert.NoError(t, newExtension.Unmarshal(expect))
	assert.Len(t, newExtension.Filters, 2)
	assert.Equal(t, oid1, newExtension.Filters[0].OID)
	assert.Equal(t, values1, newExtension.Filters[0].Values)
	assert.Equal(t, oid2, newExtension.Filters[1].OID)
	assert.Equal(t, values2, newExtension.Filters[1].Values)
}

func TestOIDFilters_DuplicateFilters(t *testing.T) {
	oid := []byte{0x55, 0x04}
	values1 := []byte{0xaa, 0xbb}
	values2 := []byte{0xcc, 0xdd}
	extension := OIDFilters{Filters: []OIDFilter{
		{OID: oid, Values: values1},
		{OID: oid, Values: values2},
	}}

	_, err := extension.Marshal()
	assert.ErrorIs(t, err, errDuplicateOID)

	raw := []byte{
		0x00, 0x30, // extension type
		0x00, 0x10, // extension data length
		0x00, 0x0e, // filter list length
		0x02,       // OID length
		0x55, 0x04, // OID bytes
		0x00, 0x02, // values length
		0xaa, 0xbb, // values bytes
		0x02,       // OID length
		0x55, 0x04, // OID bytes
		0x00, 0x02, // values length
		0xcc, 0xdd, // values bytes
	}

	newExtension := OIDFilters{}
	assert.ErrorIs(t, newExtension.Unmarshal(raw), errDuplicateOID)
}

func TestOIDFilters_EmptyValues(t *testing.T) {
	oid := []byte{0x55, 0x04, 0x03}
	extension := OIDFilters{Filters: []OIDFilter{
		{OID: oid, Values: []byte{}},
	}}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x30, // extension type
		0x00, 0x08, // extension data length
		0x00, 0x06, // filter list length
		0x03,             // OID length
		0x55, 0x04, 0x03, // OID bytes
		0x00, 0x00, // values length (empty)
	}
	assert.Equal(t, expect, raw)

	newExtension := OIDFilters{}
	assert.NoError(t, newExtension.Unmarshal(expect))
	assert.Len(t, newExtension.Filters, 1)
	assert.Equal(t, oid, newExtension.Filters[0].OID)
	assert.Empty(t, newExtension.Filters[0].Values)
}

func TestOIDFilters_EmptyFilterList(t *testing.T) {
	extension := OIDFilters{Filters: []OIDFilter{}}

	raw, err := extension.Marshal()
	assert.NoError(t, err)

	expect := []byte{
		0x00, 0x30, // extension type
		0x00, 0x02, // extension data length
		0x00, 0x00, // filter list length (empty)
	}
	assert.Equal(t, expect, raw)

	newExtension := OIDFilters{}
	assert.NoError(t, newExtension.Unmarshal(expect))
	assert.Empty(t, newExtension.Filters)
}

func TestOIDFilters_EmptyOID(t *testing.T) {
	raw := []byte{
		0x00, 0x30, // extension type
		0x00, 0x04, // extension data length
		0x00, 0x02, // filter list length
		0x00, // OID length = 0 (invalid)
		0x00, // start of values length
	}
	newExtension := OIDFilters{}
	assert.ErrorIs(t, newExtension.Unmarshal(raw), errOIDFiltersFormat)
}

func TestOIDFilters_MarshalEmptyOID(t *testing.T) {
	extension := OIDFilters{Filters: []OIDFilter{
		{OID: []byte{}, Values: []byte{0x01}},
	}}
	_, err := extension.Marshal()
	assert.ErrorIs(t, err, errEmptyOIDFilter)
}

func FuzzOIDFiltersUnmarshal(f *testing.F) {
	f.Add([]byte{
		0x00, 0x30,
		0x00, 0x0c,
		0x00, 0x0a,
		0x03, 0x55, 0x04, 0x03,
		0x00, 0x04, 0xde, 0xad, 0xbe, 0xef,
	})
	f.Add([]byte{
		0x00, 0x30,
		0x00, 0x02,
		0x00, 0x00,
	})
	f.Add([]byte{
		0x00, 0x30,
		0x00, 0x04,
		0x00, 0x02,
		0x00, 0x00,
	})
	f.Add([]byte{0x00, 0x30})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		ext := OIDFilters{}
		err := ext.Unmarshal(data)
		if err != nil {
			return
		}
		seen := map[string]struct{}{}
		for _, filter := range ext.Filters {
			assert.NotEmpty(t, filter.OID)
			_, dup := seen[string(filter.OID)]
			assert.False(t, dup)
			seen[string(filter.OID)] = struct{}{}
		}
		testExtDataLength(t, &ext, data, true)
	})
}
