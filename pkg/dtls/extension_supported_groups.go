package dtls

import (
	"encoding/binary"
)

const (
	extensionSupportedGroupsHeaderSize = 6
)

// https://tools.ietf.org/html/rfc8422
type extensionSupportedGroups struct {
	supportedGroups []namedCurve
}

func (e extensionSupportedGroups) extensionValue() extensionValue {
	return extensionSupportedGroupsValue
}

func (e *extensionSupportedGroups) marshal() ([]byte, error) {
	out := make([]byte, extensionSupportedGroupsHeaderSize)

	binary.BigEndian.PutUint16(out, uint16(e.extensionValue()))
	binary.BigEndian.PutUint16(out[2:], uint16(2+(len(e.supportedGroups)*2)))
	binary.BigEndian.PutUint16(out[4:], uint16(len(e.supportedGroups)*2))

	for _, v := range e.supportedGroups {
		out = append(out, []byte{0x00, 0x00}...)
		binary.BigEndian.PutUint16(out[len(out)-2:], uint16(v))
	}

	return out, nil
}

func (e *extensionSupportedGroups) unmarshal(data []byte) error {
	if len(data) <= extensionSupportedGroupsHeaderSize {
		return errBufferTooSmall
	} else if extensionValue(binary.BigEndian.Uint16(data)) != e.extensionValue() {
		return errInvalidExtensionType
	}

	groupCount := int(binary.BigEndian.Uint16(data[4:]) / 2)
	if extensionSupportedGroupsHeaderSize+(groupCount*2) > len(data) {
		return errLengthMismatch
	}

	for i := 0; i < groupCount; i++ {
		supportedGroupID := namedCurve(binary.BigEndian.Uint16(data[(extensionSupportedGroupsHeaderSize + (i * 2)):]))
		if _, ok := namedCurves[supportedGroupID]; ok {
			e.supportedGroups = append(e.supportedGroups, supportedGroupID)
		}
	}
	return nil
}
