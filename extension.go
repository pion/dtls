package dtls

import (
	"encoding/binary"
)

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
type extensionValue uint16

const (
	extensionSupportedEllipticCurvesValue extensionValue = 10
	extensionSupportedPointFormatsValue   extensionValue = 11
	extensionUseSRTPValue                 extensionValue = 14
)

type extension interface {
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error

	extensionValue() extensionValue
}

func decodeExtensions(buf []byte) ([]extension, error) {
	declaredLen := binary.BigEndian.Uint16(buf)
	if len(buf)-2 != int(declaredLen) {
		return nil, errLengthMismatch
	}

	extensions := []extension{}
	unmarshalAndAppend := func(data []byte, e extension) error {
		err := e.Unmarshal(data)
		if err != nil {
			return err
		}
		extensions = append(extensions, e)
		return nil
	}

	for offset := 2; offset < len(buf); {
		var err error
		switch extensionValue(binary.BigEndian.Uint16(buf[offset:])) {
		case extensionSupportedEllipticCurvesValue:
			err = unmarshalAndAppend(buf[offset:], &extensionSupportedEllipticCurves{})
		case extensionUseSRTPValue:
			err = unmarshalAndAppend(buf[offset:], &extensionUseSRTP{})
		default:
		}
		if err != nil {
			return nil, err
		}

		extensionLength := binary.BigEndian.Uint16(buf[offset+2:])
		offset += (4 + int(extensionLength))
	}
	return extensions, nil
}

func encodeExtensions(e []extension) ([]byte, error) {
	extensions := []byte{}
	for _, e := range e {
		raw, err := e.Marshal()
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, raw...)
	}
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out, uint16(len(extensions)))
	return append(out, extensions...), nil
}
