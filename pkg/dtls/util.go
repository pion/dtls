package dtls

import "encoding/binary"

// Parse a big endian uint24
func bigEndianUint24(raw []byte) uint32 {
	if len(raw) < 3 {
		return 0
	}

	rawCopy := make([]byte, 4)
	copy(rawCopy[1:], raw)
	return binary.BigEndian.Uint32(rawCopy)
}
