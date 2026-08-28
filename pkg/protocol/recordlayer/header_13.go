// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package recordlayer

import (
	"math"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
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
	if len(u.ConnectionID) > math.MaxUint8 {
		return []byte{}, dtlserrors.ErrCIDTooBig
	}

	out := make([]byte, u.MarshalSize())
	_, err := u.MarshalTo(out)

	return out, err
}

// MarshalTo encodes a DTLS 1.3 Unified Header to a pre-allocated buffer.
func (u *UnifiedHeader) MarshalTo(out []byte) (int, error) {
	cidSize := len(u.ConnectionID)
	if cidSize > math.MaxUint8 {
		return 0, dtlserrors.ErrCIDTooBig
	}
	if len(out) < u.MarshalSize() {
		return 0, dtlserrors.ErrBufferTooSmall
	}

	contentType := byte(UnifiedHeaderFixedBits) | u.EpochLow&TwoLowBitsMask
	offset := 1
	if cidSize > 0 {
		contentType |= UnifiedHeaderCIDBit
		offset += copy(out[offset:], u.ConnectionID)
	}

	if u.SeqBit {
		contentType |= UnifiedHeaderSeqBit
		out[offset] = byte(u.SequenceNumber >> 8)
		out[offset+1] = byte(u.SequenceNumber) //nolint:gosec // validated above
		offset += 2
	} else {
		out[offset] = byte(u.SequenceNumber) //nolint:gosec // truncation is prescribed by SeqBit
		offset++
	}

	if u.LengthBit {
		contentType |= UnifiedHeaderLengthBit
		out[offset] = byte(u.Length >> 8)
		out[offset+1] = byte(u.Length) //nolint:gosec // validated above
		offset += 2
	}
	out[0] = contentType

	return offset, nil
}

// Unmarshal populates a DTLS 1.3 Unified Header from binary.
func (u *UnifiedHeader) Unmarshal(data []byte) error {
	str := cryptobyte.String(data)

	var ct uint8
	if !str.ReadUint8(&ct) || !protocol.IsDTLS13Ciphertext(protocol.ContentType(ct)) {
		return dtlserrors.ErrInvalidContentType
	}

	if ct&UnifiedHeaderCIDBit != 0 {
		size := len(u.ConnectionID)
		if !str.ReadBytes(&u.ConnectionID, size) {
			return dtlserrors.ErrInvalidUnifiedHeaderFormat
		}
	} else {
		u.ConnectionID = []byte{}
	}

	if ct&UnifiedHeaderSeqBit != 0 {
		var seq uint16
		if !str.ReadUint16(&seq) {
			return dtlserrors.ErrInvalidUnifiedHeaderFormat
		}
		u.SequenceNumber = seq
		u.SeqBit = true
	} else {
		var seq uint8
		if !str.ReadUint8(&seq) {
			return dtlserrors.ErrInvalidUnifiedHeaderFormat
		}
		u.SequenceNumber = uint16(seq)
		u.SeqBit = false
	}

	u.EpochLow = ct & TwoLowBitsMask

	if ct&UnifiedHeaderLengthBit != 0 {
		var length uint16
		if !str.ReadUint16(&length) {
			return dtlserrors.ErrInvalidUnifiedHeaderFormat
		}
		u.Length = length
		u.LengthBit = true
	} else {
		u.Length = 0
		u.LengthBit = false
	}

	return nil
}

func (u *UnifiedHeader) MarshalSize() int {
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
