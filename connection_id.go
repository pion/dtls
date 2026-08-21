// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/rand"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// RandomCIDGenerator is a random Connection ID generator where CID is the
// specified size. Specifying a size of 0 will indicate to peers that sending a
// Connection ID is not necessary.
func RandomCIDGenerator(size int) func() []byte {
	return func() []byte {
		cid := make([]byte, size)
		if _, err := rand.Read(cid); err != nil {
			panic(err) //nolint -- nonrecoverable
		}

		return cid
	}
}

// OnlySendCIDGenerator enables sending Connection IDs negotiated with a peer,
// but indicates to the peer that sending Connection IDs in return is not
// necessary.
func OnlySendCIDGenerator() func() []byte {
	return func() []byte {
		return nil
	}
}

// cidDatagramRouter extracts connection IDs from incoming datagram payloads and
// uses them to route to the proper connection.
// NOTE: properly routing datagrams based on connection IDs requires using
// constant size connection IDs.
func cidDatagramRouter(size int) func([]byte) (string, bool) {
	return func(packet []byte) (string, bool) {
		if len(packet) == 0 {
			return "", false
		}
		if protocol.IsDTLS13Ciphertext(protocol.ContentType(packet[0])) {
			return cidDatagramRouter13(packet, size)
		}

		pkts, err := recordlayer.ContentAwareUnpackDatagram(packet, size)
		if err != nil || len(pkts) == 0 {
			return "", false
		}
		for _, pkt := range pkts {
			h := &recordlayer.Header{
				ConnectionID: make([]byte, size),
			}
			if err := h.Unmarshal(pkt); err != nil {
				continue
			}
			if h.ContentType != protocol.ContentTypeConnectionID {
				continue
			}

			return string(h.ConnectionID), true
		}

		return "", false
	}
}

// cidDatagramRouter13 extracts the fixed-length connection ID from a DTLS 1.3
// unified header. The CID bit is authenticated only when Conn opens the record,
// so routing by it selects a candidate connection rather than authenticating a
// peer address.
//
// https://datatracker.ietf.org/doc/html/rfc9147#section-4
func cidDatagramRouter13(packet []byte, size int) (string, bool) {
	pkts, err := recordlayer.UnpackDatagram13(packet, size, false, true)
	if err != nil || len(pkts) == 0 {
		return "", false
	}
	for _, pkt := range pkts {
		if len(pkt) == 0 ||
			!protocol.IsDTLS13Ciphertext(protocol.ContentType(pkt[0])) ||
			pkt[0]&recordlayer.UnifiedHeaderCIDBit == 0 {
			continue
		}

		h := recordlayer.UnifiedHeader{ConnectionID: make([]byte, size)}
		if err := h.Unmarshal(pkt); err != nil {
			continue
		}

		return string(h.ConnectionID), true
	}

	return "", false
}

// cidConnIdentifier extracts connection IDs from outgoing ServerHello records
// and associates them with the associated connection.
// NOTE: a ServerHello should always be the first record in a datagram if
// multiple are present, so we avoid iterating through all packets if the first
// is not a ServerHello.
func cidConnIdentifier() func([]byte) (string, bool) { //nolint:cyclop
	return func(packet []byte) (string, bool) {
		var h recordlayer.Header
		if err := h.Unmarshal(packet); err != nil {
			return "", false
		}
		if h.ContentType != protocol.ContentTypeHandshake {
			return "", false
		}
		firstRecordSize := h.Size() + int(h.ContentLen)
		if len(packet) < firstRecordSize {
			return "", false
		}
		firstRecord := packet[:firstRecordSize]

		var hh handshake.Header
		var sh handshake.MessageServerHello
		if err := hh.Unmarshal(firstRecord[recordlayer.FixedHeaderSize:]); err != nil {
			return "", false
		}
		if err := sh.Unmarshal(firstRecord[recordlayer.FixedHeaderSize+handshake.HeaderLength:]); err != nil {
			return "", false
		}
		for _, ext := range sh.Extensions {
			if e, ok := ext.(*extension.ConnectionID); ok {
				return string(e.CID), true
			}
		}

		return "", false
	}
}
