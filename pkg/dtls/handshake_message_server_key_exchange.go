package dtls

import (
	"encoding/binary"
)

// Structure only supports ECDH
type handshakeMessageServerKeyExchange struct {
	ellipticCurveType  ellipticCurveType
	namedCurve         namedCurve
	publicKey          []byte
	hashAlgorithm      hashAlgorithm
	signatureAlgorithm signatureAlgorithm
	clientRandom       *handshakeRandom
	serverRandom       *handshakeRandom
	signature          []byte
}

func (h handshakeMessageServerKeyExchange) handshakeType() handshakeType {
	return handshakeTypeServerKeyExchange
}

func (h *handshakeMessageServerKeyExchange) marshal() ([]byte, error) {
	out := []byte{byte(h.ellipticCurveType), 0x00, 0x00}
	binary.BigEndian.PutUint16(out[1:], uint16(h.namedCurve))

	out = append(out, byte(len(h.publicKey)))
	out = append(out, h.publicKey...)

	out = append(out, []byte{byte(h.hashAlgorithm), byte(h.signatureAlgorithm), 0x00, 0x00}...)

	if h.signature == nil &&
		h.clientRandom != nil &&
		h.serverRandom != nil {
		// Sign
		// - Client Hello (32)
		// - Server Hello (32)
		// - Curve info (3)
		// - Client Hello
		toSign := make([]byte, 32+32+1+3+len(h.publicKey))
		clienRandom, _ := h.clientRandom.marshal()
		copy(toSign[:32], clienRandom)
		serverRandom, _ := h.serverRandom.marshal()
		copy(toSign[32:64], serverRandom)
		copy(toSign[64:67], out[:3])
		toSign[67] = byte(len(h.publicKey))
		copy(toSign[68:], h.publicKey)

		hash := toSign // TODO: Sign

		h.signature = append(h.signature, byte(h.hashAlgorithm), byte(h.signatureAlgorithm)) // reserved value for RSA signature with SHA256 hash
		h.signature = append(h.signature, 0x01, 0x00)                                        // length of signature (0x100 or 256 bytes)
		h.signature = append(h.signature, hash[:]...)

	}

	binary.BigEndian.PutUint16(out[len(out)-2:], uint16(len(h.signature)))
	out = append(out, h.signature...)

	return out, nil
}

func (h *handshakeMessageServerKeyExchange) unmarshal(data []byte) error {
	if _, ok := ellipticCurveTypes[ellipticCurveType(data[0])]; ok {
		h.ellipticCurveType = ellipticCurveType(data[0])
	} else {
		return errInvalidEllipticCurveType
	}

	h.namedCurve = namedCurve(binary.BigEndian.Uint16(data[1:]))
	if _, ok := namedCurves[h.namedCurve]; !ok {
		return errInvalidNamedCurve
	}

	publicKeyLength := int(data[3])
	offset := 4 + publicKeyLength
	if len(data) <= publicKeyLength {
		return errBufferTooSmall
	}
	h.publicKey = append([]byte{}, data[4:offset]...)

	h.hashAlgorithm = hashAlgorithm(data[offset])
	if _, ok := hashAlgorithms[h.hashAlgorithm]; !ok {
		return errInvalidHashAlgorithm
	}
	offset++

	h.signatureAlgorithm = signatureAlgorithm(data[offset])
	if _, ok := signatureAlgorithms[h.signatureAlgorithm]; !ok {
		return errInvalidSignatureAlgorithm
	}
	offset++

	signatureLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	h.signature = append([]byte{}, data[offset:offset+signatureLength]...)
	return nil
}
