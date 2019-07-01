package dtls

import "encoding/binary"

type handshakeMessageClientKeyExchange struct {
	pskIdentity []byte
	publicKey   []byte
}

func (h handshakeMessageClientKeyExchange) handshakeType() handshakeType {
	return handshakeTypeClientKeyExchange
}

func (h *handshakeMessageClientKeyExchange) Marshal() ([]byte, error) {
	switch {
	case (len(h.pskIdentity) != 0 && len(h.publicKey) != 0) || (len(h.pskIdentity) == 0 && len(h.publicKey) == 0):
		return nil, errInvalidClientKeyExchange
	case len(h.publicKey) != 0:
		return append([]byte{byte(len(h.publicKey))}, h.publicKey...), nil
	default:
		out := append([]byte{0x00, 0x00}, h.pskIdentity...)
		binary.BigEndian.PutUint16(out, uint16(len(out)-2))
		return out, nil
	}
}

func (h *handshakeMessageClientKeyExchange) Unmarshal(data []byte) error {
	pskIdentityUnmarshal := func() error {
		if len(data) < 2 {
			return errBufferTooSmall
		}

		pskLength := binary.BigEndian.Uint16(data)
		if len(data) <= int(pskLength) {
			return errBufferTooSmall
		}

		h.pskIdentity = append([]byte{}, data[2:]...)
		return nil
	}

	if len(data) < 1 {
		return errBufferTooSmall
	}

	publicKeyLength := int(data[0])
	if len(data) <= publicKeyLength {
		// ClientKeyExchange may be PSK Identity, uint16 instead of byte is used for length
		return pskIdentityUnmarshal()
	}

	h.publicKey = append([]byte{}, data[1:]...)
	return nil
}
