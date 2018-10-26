package dtls

import "encoding/binary"

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
type extensionValue uint16

const (
	extensionSupportedGroupsValue extensionValue = 10
	extensionUseSRTPValue                        = 14
)

type extension interface {
	marshal() ([]byte, error)
	unmarshal(data []byte) error

	extensionValue() extensionValue
}

func encodeExtensions(e []extension) ([]byte, error) {
	extensions := []byte{}
	for _, e := range e {
		raw, err := e.marshal()
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, raw...)
	}
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out, uint16(len(extensions)))
	return append(out, extensions...), nil
}
