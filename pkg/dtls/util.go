package dtls

import (
	"encoding/binary"
)

// Parse a big endian uint24
func bigEndianUint24(raw []byte) uint32 {
	if len(raw) < 3 {
		return 0
	}

	rawCopy := make([]byte, 4)
	copy(rawCopy[1:], raw)
	return binary.BigEndian.Uint32(rawCopy)
}

func putBigEndianUint24(out []byte, in uint32) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, in)
	copy(out, tmp[1:])
}
