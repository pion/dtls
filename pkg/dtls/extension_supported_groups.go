package dtls

import (
	"encoding/binary"
)

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type supportedGroup uint16

const (
	supportedGroupP256 supportedGroup = 23
)

const (
	extensionSupportedGroupsHeaderSize = 6
)

// https://tools.ietf.org/html/rfc8422
type extensionSupportedGroups struct {
	supportedGroups []supportedGroup
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
	return errNotImplemented
}
