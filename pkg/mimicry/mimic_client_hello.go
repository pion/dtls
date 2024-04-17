package mimicry

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/pion/dtls/v2/pkg/protocol/handshake"
)

type MimickedClientHello struct {
	Random handshake.Random
}

func (m MimickedClientHello) Type() handshake.Type {
	return handshake.TypeClientHello
}

func (m *MimickedClientHello) Marshal() ([]byte, error) {
	if len(fingerprints) < 1 {
		return nil, errors.New("No fingerprints available")
	}
	fingerprint := fingerprints[0]

	// TODO: check for Cookie and SessionID in mimicked packet
	randomOffset := 2

	rb := m.Random.MarshalFixed()

	data, err := hex.DecodeString(fingerprint)
	if err != nil {
		err = errors.New(fmt.Sprintf("Mimicry: failed to decode mimicry hexstring: %x", fingerprint))
	}

	return bytes.Replace(data, data[randomOffset:randomOffset+32], rb[:], 32), err
}

func (m *MimickedClientHello) Unmarshal(data []byte) error { return nil }
