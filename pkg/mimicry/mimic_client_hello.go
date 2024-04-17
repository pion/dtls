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

func getClientHello(r handshake.Random) ([]byte, error) {
	// TODO: check for Cookie and SessionID in mimicked packet
	chromium_123_0_6312_0 := "fefd992e494148b49611343c53cba30af13026f0961c5737701da2e56ac2c842038a00000016c02bc02fcca9cca8c009c013c00ac014009c002f00350100004400170000ff01000100000a00080006001d00170018000b0002010000230000000d00140012040308040401050308050501080606010201000e0009000600010008000700"

	randomOffset := 2

	rb := r.MarshalFixed()

	data, err := hex.DecodeString(chromium_123_0_6312_0)
	if err != nil {
		err = errors.New(fmt.Sprintf("Mimicry: failed to decode mimicry hexstring: %x", chromium_123_0_6312_0))
	}

	return bytes.Replace(data, data[randomOffset:randomOffset+32], rb[:], 32), err
}

func (m MimickedClientHello) Type() handshake.Type {
	return handshake.TypeClientHello
}

func (m *MimickedClientHello) Marshal() ([]byte, error) {
	return getClientHello(m.Random)
}

func (m *MimickedClientHello) Unmarshal(data []byte) error { return nil }
