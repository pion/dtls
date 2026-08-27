// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"bytes"
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// OIDFilter contains one certificate extension OID and its requested values.
type OIDFilter struct {
	OID    []byte
	Values []byte
}

// OIDFilters is the oid_filters payload.
type OIDFilters struct {
	Filters []OIDFilter
}

// ExtensionType returns the IANA extension type.
func (OIDFilters) ExtensionType() extension.Type { return extension.TypeOIDFilters }

// MarshalSize returns the encoded payload size without serializing it.
func (o OIDFilters) MarshalSize() int {
	total := 2
	for _, filter := range o.Filters {
		total += 3 + len(filter.OID) + len(filter.Values)
	}

	return total
}

// MarshalData encodes extension_data.
func (o OIDFilters) MarshalData() ([]byte, error) {
	filters := make([]byte, 0)
	seen := map[string]struct{}{}
	for _, filter := range o.Filters {
		if len(filter.OID) == 0 || len(filter.OID) > 255 {
			return nil, dtlserrors.ErrEmptyOIDFilter
		}
		if _, ok := seen[string(filter.OID)]; ok {
			return nil, dtlserrors.ErrDuplicateOID
		}
		seen[string(filter.OID)] = struct{}{}
		if len(filter.Values) > 0xffff || len(filters) > 0xffff-3-len(filter.OID)-len(filter.Values) {
			return nil, dtlserrors.ErrOIDFiltersFormat
		}

		filters = append(filters, byte(len(filter.OID))) //nolint:gosec // bounded above.
		filters = append(filters, filter.OID...)
		filters = binary.BigEndian.AppendUint16(filters, uint16(len(filter.Values))) //nolint:gosec // bounded above.
		filters = append(filters, filter.Values...)
	}

	out := make([]byte, 2, 2+len(filters))
	binary.BigEndian.PutUint16(out, uint16(len(filters))) //nolint:gosec // bounded above.
	out = append(out, filters...)

	return out, nil
}

// UnmarshalData decodes extension_data.
func (o *OIDFilters) UnmarshalData(data []byte) error { //nolint:cyclop
	if len(data) < 2 {
		return dtlserrors.ErrLengthMismatch
	}
	length := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	if length != len(data) {
		return dtlserrors.ErrLengthMismatch
	}

	filters := make([]OIDFilter, 0)
	seen := map[string]struct{}{}
	for len(data) > 0 {
		oidLen := int(data[0])
		data = data[1:]
		if oidLen == 0 || oidLen > len(data) {
			return dtlserrors.ErrOIDFiltersFormat
		}
		oid := bytes.Clone(data[:oidLen])
		data = data[oidLen:]
		if _, ok := seen[string(oid)]; ok {
			return dtlserrors.ErrDuplicateOID
		}
		seen[string(oid)] = struct{}{}

		if len(data) < 2 {
			return dtlserrors.ErrOIDFiltersFormat
		}
		valuesLen := int(binary.BigEndian.Uint16(data))
		data = data[2:]
		if valuesLen > len(data) {
			return dtlserrors.ErrOIDFiltersFormat
		}
		filters = append(filters, OIDFilter{OID: oid, Values: bytes.Clone(data[:valuesLen])})
		data = data[valuesLen:]
	}

	o.Filters = filters

	return nil
}
