package dtls

import ( //nolint:gci
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"

	"github.com/pion/dtls/v2/internal/util"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
)

// block ciphers using cipher block chaining.
type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

// State needed to handle encrypted input/output
type cryptoCBC struct {
	writeCBC, readCBC cbcMode
	writeMac, readMac []byte
	h                 hashFunc
}

func newCryptoCBC(localKey, localWriteIV, localMac, remoteKey, remoteWriteIV, remoteMac []byte, h hashFunc) (*cryptoCBC, error) {
	writeBlock, err := aes.NewCipher(localKey)
	if err != nil {
		return nil, err
	}

	readBlock, err := aes.NewCipher(remoteKey)
	if err != nil {
		return nil, err
	}

	return &cryptoCBC{
		writeCBC: cipher.NewCBCEncrypter(writeBlock, localWriteIV).(cbcMode),
		writeMac: localMac,

		readCBC: cipher.NewCBCDecrypter(readBlock, remoteWriteIV).(cbcMode),
		readMac: remoteMac,
		h:       h,
	}, nil
}

func (c *cryptoCBC) encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error) {
	payload := raw[recordlayer.HeaderSize:]
	raw = raw[:recordlayer.HeaderSize]
	blockSize := c.writeCBC.BlockSize()

	// Generate + Append MAC
	h := pkt.Header

	MAC, err := prfMac(h.Epoch, h.SequenceNumber, h.ContentType, h.Version, payload, c.writeMac, c.h)
	if err != nil {
		return nil, err
	}
	payload = append(payload, MAC...)

	// Generate + Append padding
	padding := make([]byte, blockSize-len(payload)%blockSize)
	paddingLen := len(padding)
	for i := 0; i < paddingLen; i++ {
		padding[i] = byte(paddingLen - 1)
	}
	payload = append(payload, padding...)

	// Generate IV
	iv := make([]byte, blockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Set IV + Encrypt + Prepend IV
	c.writeCBC.SetIV(iv)
	c.writeCBC.CryptBlocks(payload, payload)
	payload = append(iv, payload...)

	// Prepend unencrypte header with encrypted payload
	raw = append(raw, payload...)

	// Update recordLayer size to include IV+MAC+Padding
	binary.BigEndian.PutUint16(raw[recordlayer.HeaderSize-2:], uint16(len(raw)-recordlayer.HeaderSize))

	return raw, nil
}

func (c *cryptoCBC) decrypt(in []byte) ([]byte, error) {
	body := in[recordlayer.HeaderSize:]
	blockSize := c.readCBC.BlockSize()
	mac := c.h()

	var h recordlayer.Header
	err := h.Unmarshal(in)
	switch {
	case err != nil:
		return nil, err
	case h.ContentType == protocol.ContentTypeChangeCipherSpec:
		// Nothing to encrypt with ChangeCipherSpec
		return in, nil
	case len(body)%blockSize != 0 || len(body) < blockSize+util.Max(mac.Size()+1, blockSize):
		return nil, errNotEnoughRoomForNonce
	}

	// Set + remove per record IV
	c.readCBC.SetIV(body[:blockSize])
	body = body[blockSize:]

	// Decrypt
	c.readCBC.CryptBlocks(body, body)

	// Padding+MAC needs to be checked in constant time
	// Otherwise we reveal information about the level of correctness
	paddingLen, paddingGood := examinePadding(body)

	macSize := mac.Size()
	if len(body) < macSize {
		return nil, errInvalidMAC
	}

	dataEnd := len(body) - macSize - paddingLen

	expectedMAC := body[dataEnd : dataEnd+macSize]
	actualMAC, err := prfMac(h.Epoch, h.SequenceNumber, h.ContentType, h.Version, body[:dataEnd], c.readMac, c.h)

	// Compute Local MAC and compare
	if paddingGood != 255 || err != nil || !hmac.Equal(actualMAC, expectedMAC) {
		return nil, errInvalidMAC
	}

	return append(in[:recordlayer.HeaderSize], body[:dataEnd]...), nil
}
