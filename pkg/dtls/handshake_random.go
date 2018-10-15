package dtls

import (
	"encoding/binary"
	"time"
)

const handshakeRandomLength = 32

// https://tools.ietf.org/html/rfc4346#section-7.4.1.2
type handshakeRandom struct {
	gmtUnixTime time.Time
	randomBytes [28]byte
}

func (h *handshakeRandom) marshal() ([]byte, error) {
	return nil, errNotImplemented
}

func (h *handshakeRandom) unmarshal(data []byte) error {
	if len(data) != handshakeRandomLength {
		return errBufferTooSmall
	}
	h.gmtUnixTime = time.Unix(int64(binary.BigEndian.Uint32(data[0:])), 0)
	copy(h.randomBytes[:], data[4:])

	return nil
}

// populate fills the handshakeRandom with random values
// may be called multiple times
func (h *handshakeRandom) populate() {
}
