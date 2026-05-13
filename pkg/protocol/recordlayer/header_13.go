// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"math"

	"github.com/pion/dtls/v3/pkg/protocol"
	"golang.org/x/crypto/cryptobyte"
)

// UnifiedHeader implements the DTLS 1.3 Unified Header.
// See RFC 9147 section 4. The DTLS Record Layer
//
// https://datatracker.ietf.org/doc/html/rfc9147#name-the-dtls-record-layer
//
//	 0 1 2 3 4 5 6 7
//	+-+-+-+-+-+-+-+-+
//	|0|0|1|C|S|L|E E|
//	+-+-+-+-+-+-+-+-+
//	| Connection ID |   Legend:
//	| (if any,      |
//	/  length as    /   C   - Connection ID (CID) present
//	|  negotiated)  |   S   - Sequence number length
//	+-+-+-+-+-+-+-+-+   L   - Length present
//	|  8 or 16 bit  |   E   - Epoch
//	|Sequence Number|
//	+-+-+-+-+-+-+-+-+
//	| 16 bit Length |
//	| (if present)  |
//	+-+-+-+-+-+-+-+-+
type UnifiedHeader struct {
	ConnectionID   []byte // size of array should be expected CID length
	SequenceNumber uint16
	SeqBit         bool
	Length         uint16
	LengthBit      bool
	EpochLow       uint8
}

const (
	UnifiedHeaderFixedBits = 0b00100000
	UnifiedHeaderCIDBit    = 0b00010000
	UnifiedHeaderSeqBit    = 0b00001000
	UnifiedHeaderLengthBit = 0b00000100
	TwoLowBitsMask         = 0b11
)

// Marshal encodes a DTLS 1.3 Unified Header to binary.
func (u *UnifiedHeader) Marshal() ([]byte, error) {
	var contentType uint8
	var head cryptobyte.Builder
	contentType = UnifiedHeaderFixedBits

	cidSz := len(u.ConnectionID)
	if cidSz > 0 {
		contentType |= UnifiedHeaderCIDBit
		if cidSz > math.MaxUint8 {
			return []byte{}, errCIDTooBig
		}
		head.AddBytes(u.ConnectionID)
	}

	if u.SeqBit {
		contentType |= UnifiedHeaderSeqBit
		head.AddUint16(u.SequenceNumber)
	} else {
		head.AddUint8(uint8(u.SequenceNumber)) //nolint:gosec
	}

	if u.LengthBit {
		contentType |= UnifiedHeaderLengthBit
		head.AddUint16(u.Length)
	}

	contentType |= u.EpochLow & TwoLowBitsMask

	headBytes, err := head.Bytes()
	if err != nil {
		return []byte{}, err
	}
	out := make([]byte, 1+len(headBytes))
	out[0] = contentType
	copy(out[1:], headBytes)

	return out, nil
}

// Unmarshal populates a DTLS 1.3 Unified Header from binary.
func (u *UnifiedHeader) Unmarshal(data []byte) error {
	str := cryptobyte.String(data)

	var ct uint8
	if !str.ReadUint8(&ct) || !protocol.IsDTLS13Ciphertext(protocol.ContentType(ct)) {
		return errInvalidContentType
	}

	if ct&UnifiedHeaderCIDBit != 0 {
		size := len(u.ConnectionID)
		if !str.ReadBytes(&u.ConnectionID, size) {
			return errInvalidUnifiedHeaderFormat
		}
	} else {
		u.ConnectionID = []byte{}
	}

	if ct&UnifiedHeaderSeqBit != 0 {
		var seq uint16
		if !str.ReadUint16(&seq) {
			return errInvalidUnifiedHeaderFormat
		}
		u.SequenceNumber = seq
		u.SeqBit = true
	} else {
		var seq uint8
		if !str.ReadUint8(&seq) {
			return errInvalidUnifiedHeaderFormat
		}
		u.SequenceNumber = uint16(seq)
		u.SeqBit = false
	}

	u.EpochLow = ct & TwoLowBitsMask

	if ct&UnifiedHeaderLengthBit != 0 {
		var length uint16
		if !str.ReadUint16(&length) {
			return errInvalidUnifiedHeaderFormat
		}
		u.Length = length
		u.LengthBit = true
	} else {
		u.Length = 0
		u.LengthBit = false
	}

	return nil
}

func (u *UnifiedHeader) Size() int {
	var size int
	size += 1
	size += len(u.ConnectionID)
	if u.SeqBit {
		size += 2
	} else {
		size += 1
	}
	if u.LengthBit {
		size += 2
	}

	return size
}
