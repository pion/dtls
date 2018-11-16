package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
)

const aesGCMTagLength = 16

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func encryptPacket(pkt *recordLayer, raw, localWriteIV []byte, localGCM cipher.AEAD) []byte {
	payload := raw[recordLayerHeaderSize:]
	raw = raw[:recordLayerHeaderSize]

	nonce := append(append([]byte{}, localWriteIV[:4]...), make([]byte, 8)...)
	if _, err := rand.Read(nonce[4:]); err != nil {
		panic(err)
	}

	var additionalData [13]byte
	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(additionalData[:], pkt.recordLayerHeader.sequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], pkt.recordLayerHeader.epoch)
	additionalData[8] = byte(pkt.content.contentType())
	additionalData[9] = pkt.recordLayerHeader.protocolVersion.major
	additionalData[10] = pkt.recordLayerHeader.protocolVersion.minor
	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(len(payload)))
	encryptedPayload := localGCM.Seal(nil, nonce, payload, additionalData[:])

	encryptedPayload = append(nonce[4:], encryptedPayload...)
	raw = append(raw, encryptedPayload...)

	// Update recordLayer size to include explicit nonce
	binary.BigEndian.PutUint16(raw[recordLayerHeaderSize-2:], uint16(len(raw)-recordLayerHeaderSize))
	return raw
}

func decryptPacket(in, remoteWriteIV []byte, remoteGCM cipher.AEAD) ([]byte, error) {
	var h recordLayerHeader
	if err := h.unmarshal(in); err != nil {
		return nil, err
	} else if h.contentType != contentTypeHandshake && h.contentType != contentTypeApplicationData {
		// Only ApplicationData + Handshake can be encrypted
		return in, nil
	} else if len(in) <= (8 + recordLayerHeaderSize) {
		return nil, errNotEnoughRoomForNonce
	}

	nonce := append(remoteWriteIV[:4], in[recordLayerHeaderSize:recordLayerHeaderSize+8]...)
	out := in[recordLayerHeaderSize+8:]

	var additionalData [13]byte
	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(additionalData[:], h.sequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], h.epoch)
	additionalData[8] = byte(h.contentType)
	additionalData[9] = h.protocolVersion.major
	additionalData[10] = h.protocolVersion.minor
	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(len(out)-aesGCMTagLength))
	out, err := remoteGCM.Open(out[:0], nonce, out, additionalData[:])
	if err != nil {
		return nil, err
	}
	return append(in[:recordLayerHeaderSize], out...), nil
}
