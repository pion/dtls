// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"encoding/binary"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

const newConnectionIDMaxListLength = 65535

// ConnectionIDUsage indicates whether new CIDs should be used immediately or
// retained for future use.
type ConnectionIDUsage uint8

// ConnectionIDUsage values.
const (
	ConnectionIDImmediate ConnectionIDUsage = iota
	ConnectionIDSpare
)

// MessageNewConnectionID supplies CIDs for a peer to use when sending records.
//
// https://datatracker.ietf.org/doc/html/rfc9147#section-9
type MessageNewConnectionID struct {
	CIDs  [][]byte
	Usage ConnectionIDUsage
}

// Type returns the Handshake Type.
func (m MessageNewConnectionID) Type() Type {
	return TypeNewConnectionID
}

// Marshal encodes the Handshake.
func (m *MessageNewConnectionID) Marshal() ([]byte, error) {
	if m.Usage != ConnectionIDImmediate && m.Usage != ConnectionIDSpare {
		return nil, dtlserrors.ErrInvalidConnectionIDUsage
	}

	cidsLength := 0
	for _, cid := range m.CIDs {
		if len(cid) > 255 {
			return nil, dtlserrors.ErrCIDTooBig
		}
		cidsLength += 1 + len(cid)
		if cidsLength > newConnectionIDMaxListLength {
			return nil, dtlserrors.ErrCIDTooBig
		}
	}

	out := make([]byte, 2, 2+cidsLength+1)
	binary.BigEndian.PutUint16(out, uint16(cidsLength)) //nolint:gosec // length is checked above
	for _, cid := range m.CIDs {
		out = append(out, byte(len(cid))) //nolint:gosec // length is checked above
		out = append(out, cid...)
	}
	out = append(out, byte(m.Usage))

	return out, nil
}

// Unmarshal populates the message from encoded data.
func (m *MessageNewConnectionID) Unmarshal(data []byte) error {
	if len(data) < 3 {
		return dtlserrors.ErrBufferTooSmall
	}

	cidsLength := int(binary.BigEndian.Uint16(data))
	if len(data) != 2+cidsLength+1 {
		return dtlserrors.ErrLengthMismatch
	}

	cids := make([][]byte, 0)
	cidsData := data[2 : 2+cidsLength]
	for len(cidsData) > 0 {
		cidLength := int(cidsData[0])
		cidsData = cidsData[1:]
		if cidLength > len(cidsData) {
			return dtlserrors.ErrLengthMismatch
		}
		cid := make([]byte, cidLength)
		copy(cid, cidsData[:cidLength])
		cids = append(cids, cid)
		cidsData = cidsData[cidLength:]
	}

	usage := ConnectionIDUsage(data[len(data)-1])
	if usage != ConnectionIDImmediate && usage != ConnectionIDSpare {
		return dtlserrors.ErrInvalidConnectionIDUsage
	}

	m.CIDs = cids
	m.Usage = usage

	return nil
}
