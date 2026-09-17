// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package recordwire supplies shared header layout for framing and protection.
package recordwire

import (
	"encoding/binary"
	"math"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
)

const (
	FixedHeaderSize   = 13
	MaxSequenceNumber = 0x0000ffffffffffff
	UnifiedFixedBits  = 0x20
	CIDBit            = 0x10
	SequenceBit       = 0x08
	LengthBit         = 0x04
	EpochMask         = 0x03
)

// DecodeHeader returns the header and payload lengths. It validates the header;
// callers check that the payload fits their record or datagram.
//
//nolint:cyclop
func DecodeHeader(raw []byte, cidLength int) (headerLen, payloadLen int, err error) {
	if len(raw) == 0 || cidLength < 0 || cidLength > math.MaxUint8 {
		return 0, 0, dtlserrors.ErrInvalidPacketLength
	}
	unified := protocol.IsDTLS13Ciphertext(protocol.ContentType(raw[0]))
	hasCID := raw[0] == byte(protocol.ContentTypeConnectionID)
	if unified {
		hasCID = raw[0]&CIDBit != 0
	}
	if !hasCID {
		cidLength = 0
	} else if cidLength == 0 {
		return 0, 0, dtlserrors.ErrInvalidPacketLength
	}
	headerLen = FixedHeaderSize + cidLength
	hasLength := true
	if unified {
		headerLen = 2 + cidLength
		if raw[0]&SequenceBit != 0 {
			headerLen++
		}
		hasLength = raw[0]&LengthBit != 0
		if hasLength {
			headerLen += 2
		}
	}
	if len(raw) < headerLen {
		return 0, 0, dtlserrors.ErrInvalidPacketLength
	}
	payloadLen = len(raw) - headerLen
	if hasLength {
		payloadLen = int(binary.BigEndian.Uint16(raw[headerLen-2:]))
	}

	return headerLen, payloadLen, nil
}

// AppendUnifiedHeader appends the selected C/S/L layout without canonicalizing it.
//
//nolint:cyclop
func AppendUnifiedHeader(
	dst []byte, epochLow uint8, sequence uint16, twoBytes bool, cid []byte, hasLength bool, payloadLen int,
) ([]byte, error) {
	if epochLow > EpochMask {
		return nil, dtlserrors.ErrInvalidEpoch
	}
	if !twoBytes && sequence > math.MaxUint8 {
		return nil, dtlserrors.ErrSequenceNumberOverflow
	}
	if len(cid) > math.MaxUint8 {
		return nil, dtlserrors.ErrCIDTooBig
	}
	if payloadLen < 0 || payloadLen > math.MaxUint16 {
		return nil, dtlserrors.ErrInvalidPacketLength
	}
	first := byte(UnifiedFixedBits) | epochLow
	if len(cid) != 0 {
		first |= CIDBit
	}
	if twoBytes {
		first |= SequenceBit
	}
	if hasLength {
		first |= LengthBit
	}
	dst = append(dst, first)
	dst = append(dst, cid...)
	if twoBytes {
		dst = append(dst, byte(sequence>>8))
	}
	dst = append(dst, byte(sequence&0xff))
	if hasLength {
		dst = binary.BigEndian.AppendUint16(dst, uint16(payloadLen))
	} //nolint:gosec // Checked above.

	return dst, nil
}
