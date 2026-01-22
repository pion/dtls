// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ciphersuite

import (
	"crypto/aes"
	"encoding/binary"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
)

func FuzzCCM_EncryptDecrypt_RoundTrip(f *testing.F) {
	f.Add(byte(8), []byte{1, 2, 3, 4, 5}, uint16(0), uint64(0))
	f.Add(byte(16), []byte{}, uint16(1), uint64(7))
	f.Add(byte(8), make([]byte, 64), uint16(3), uint64(42))

	f.Fuzz(func(t *testing.T, tagLenByte byte, payload []byte, epoch uint16, seq uint64) {
		tag := CCMTagLength8
		if tagLenByte%2 == 0 {
			tag = CCMTagLength
		}

		key := make([]byte, 16)
		for i := range key {
			var b byte

			if i < len(payload) {
				b = payload[i]
			} else {
				b = byte(i*31 + 7)
			}

			key[i] = b
		}

		var tmp8 [8]byte
		x := seq ^ 0xA5A5A5A5A5A5A5A5
		binary.BigEndian.PutUint64(tmp8[:], x)
		iv := append([]byte(nil), tmp8[4:]...)

		ccm, err := NewCCM(tag, key, iv, key, iv)
		assert.NoError(t, err)

		rl := &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				ContentType:    protocol.ContentTypeApplicationData,
				Version:        protocol.Version1_2,
				Epoch:          epoch,
				SequenceNumber: seq,
			},
			Content: &protocol.ApplicationData{
				Data: append([]byte(nil), payload...),
			},
		}
		raw, err := rl.Marshal()
		assert.NoError(t, err)

		enc, err := ccm.Encrypt(rl, raw)
		assert.NoError(t, err)

		var hdr recordlayer.Header
		dec, err := ccm.Decrypt(hdr, enc)
		assert.NoError(t, err)

		var out recordlayer.RecordLayer
		assert.NoError(t, out.Unmarshal(dec))

		app, ok := out.Content.(*protocol.ApplicationData)
		assert.True(t, ok)
		assert.Equal(t, payload, app.Data)
	})
}

func FuzzCCM_Decrypt(f *testing.F) {
	f.Add([]byte{1, 2, 3})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, body []byte) {
		recordLayer := &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				ContentType: protocol.ContentTypeChangeCipherSpec,
				Version:     protocol.Version1_2,
			},
			Content: &protocol.ChangeCipherSpec{},
		}

		raw, err := recordLayer.Marshal()
		assert.NoError(t, err)
		raw = append(raw, body...) // arbitrary body after the header for fuzzing

		key := make([]byte, 16)
		_, err = aes.NewCipher(key)
		assert.NoError(t, err)

		ccmAEAD, err := NewCCM(CCMTagLength8, key, []byte{0, 0, 0, 0}, key, []byte{0, 0, 0, 0})
		assert.NoError(t, err)

		out, err := ccmAEAD.Decrypt(recordlayer.Header{}, raw)
		assert.NoError(t, err)
		assert.Equal(t, raw, out)
	})
}
