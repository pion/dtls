package dtls

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const aesGCMTagLength = 16

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

func encryptPacket(pkt *recordLayer, raw, localWriteIV []byte, localGCM cipher.AEAD) ([]byte, error) {
	payload := raw[recordLayerHeaderSize:]
	raw = raw[:recordLayerHeaderSize]

	nonce := append(append([]byte{}, localWriteIV[:4]...), make([]byte, 8)...)
	if _, err := rand.Read(nonce[4:]); err != nil {
		return nil, err
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
	return raw, nil
}

func decryptPacket(in, remoteWriteIV []byte, remoteGCM cipher.AEAD) ([]byte, error) {
	var h recordLayerHeader
	if err := h.Unmarshal(in); err != nil {
		return nil, err
	} else if h.contentType == contentTypeChangeCipherSpec {
		// Nothing to encrypt with ChangeCipherSpec
		return in, nil
	} else if len(in) <= (8 + recordLayerHeaderSize) {
		return nil, errNotEnoughRoomForNonce
	}

	nonce := append(append([]byte{}, remoteWriteIV[:4]...), in[recordLayerHeaderSize:recordLayerHeaderSize+8]...)
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
		return nil, fmt.Errorf("decryptPacket: %v", err)
	}
	return append(in[:recordLayerHeaderSize], out...), nil
}

// If the client provided a "signature_algorithms" extension, then all
// certificates provided by the server MUST be signed by a
// hash/signature algorithm pair that appears in that extension
//
// https://tools.ietf.org/html/rfc5246#section-7.4.2
func generateKeySignature(clientRandom, serverRandom, publicKey []byte, namedCurve namedCurve, privateKey crypto.PrivateKey) ([]byte, error) {
	serverECDHParams := make([]byte, 4)
	serverECDHParams[0] = 3 // named curve
	binary.BigEndian.PutUint16(serverECDHParams[1:], uint16(namedCurve))
	serverECDHParams[3] = byte(len(publicKey))

	h := sha256.New()
	h.Write(clientRandom)
	h.Write(serverRandom)
	h.Write(serverECDHParams)
	h.Write(publicKey)
	hashed := h.Sum(nil)

	switch p := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return p.Sign(rand.Reader, hashed[:], crypto.SHA256)
	case *rsa.PrivateKey:
		return p.Sign(rand.Reader, hashed[:], crypto.SHA256)
	}

	return nil, errInvalidSignatureAlgorithm
}

// If the server has sent a CertificateRequest message, the client MUST send the Certificate
// message.  The ClientKeyExchange message is now sent, and the content
// of that message will depend on the public key algorithm selected
// between the ClientHello and the ServerHello.  If the client has sent
// a certificate with signing ability, a digitally-signed
// CertificateVerify message is sent to explicitly verify possession of
// the private key in the certificate.
// https://tools.ietf.org/html/rfc5246#section-7.3
func generateCertificateVerify(handshakeBodies []byte, privateKey crypto.PrivateKey) ([]byte, error) {
	h := sha256.New()
	h.Write(handshakeBodies)
	hashed := h.Sum(nil)

	switch p := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return p.Sign(rand.Reader, hashed[:], crypto.SHA256)
	case *rsa.PrivateKey:
		return p.Sign(rand.Reader, hashed[:], crypto.SHA256)
	}

	return nil, errInvalidSignatureAlgorithm
}
