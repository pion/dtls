// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/rand"
	"errors"
	"net"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
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

type returnRoutabilityConn struct {
	conn *Conn
}

func (c returnRoutabilityConn) WriteRRC(ctx context.Context, addr net.Addr, messageType protocol.ReturnRoutabilityCheckMessageType, cookie [protocol.ReturnRoutabilityCheckCookieLength]byte) error {
	c.conn.writeLock.Lock()
	defer c.conn.writeLock.Unlock()

	c.conn.lock.Lock()
	common := dtlsstate.CommonState(c.conn.state)
	if c.conn.cidPathMigrationPolicy != CIDPathMigrationRRC || !common.RRCNegotiated {
		c.conn.lock.Unlock()

		return dtlserrors.ErrUnexpectedPostHandshakeMessage
	}
	packet := &dtlsflight.Outbound{Epoch: common.LocalEpoch(), Content: &protocol.ReturnRoutabilityCheck{MessageType: messageType, Cookie: cookie}, Protection: dtlsflight.ProtectionCiphertext}
	raw, err := c.conn.prepareRecord(packet)
	if err == nil {
		err = c.conn.rrc.Reserve(addr, c.conn.rAddr, len(raw))
	}
	c.conn.lock.Unlock()
	if err != nil {
		return err
	}

	if _, err = c.conn.nextConn.WriteToContext(ctx, raw, addr); err != nil {
		if errors.Is(err, context.Canceled) && c.conn.isConnectionClosed() {
			return ErrConnClosed
		}

		return netError(err)
	}

	return nil
}

func (c returnRoutabilityConn) HandleRecord(ctx context.Context, message *protocol.ReturnRoutabilityCheck, prepared incomingPacketState, addr net.Addr) (bool, packetOutcome, error) {
	if c.conn.cidPathMigrationPolicy != CIDPathMigrationRRC || prepared.header.Epoch == 0 || !dtlsstate.CommonState(c.conn.state).RRCNegotiated {
		return false, packetOutcome{responseAlert: &alert.Alert{Level: alert.Fatal, Description: alert.UnexpectedMessage}}, dtlserrors.ErrUnexpectedPostHandshakeMessage
	}
	isLatestSeqNum := prepared.markPacketAsValid()
	var err error
	switch message.MessageType {
	case protocol.ReturnRoutabilityCheckPathChallenge:
		err = c.WriteRRC(ctx, addr, protocol.ReturnRoutabilityCheckPathResponse, message.Cookie)
	case protocol.ReturnRoutabilityCheckPathResponse:
		if c.conn.rrc.HandleResponse(addr, message.Cookie) {
			c.conn.lock.Lock()
			c.conn.rAddr = addr
			c.conn.lock.Unlock()
		}
		isLatestSeqNum = false
	case protocol.ReturnRoutabilityCheckPathDrop:
		isLatestSeqNum = false
	default:
		// In addition, implementations MUST be able to parse and gracefully
		// ignore messages with an unknown msg_type.
		// https://datatracker.ietf.org/doc/html/rfc9853#section-4
		isLatestSeqNum = false
	}
	if err != nil {
		c.conn.log.Debugf("unable to handle return routability message: %v", err)
	}

	return isLatestSeqNum, packetOutcome{}, nil
}

func (c returnRoutabilityConn) HandleCandidate(
	ctx context.Context,
	rrcNegotiated, hasCID, latest bool,
	addr net.Addr,
) {
	if !hasCID || !latest {
		return
	}

	currentAddr := c.conn.RemoteAddr()
	if sameNetworkAddress(currentAddr, addr) {
		return
	}
	if !c.useCandidatePath(rrcNegotiated, currentAddr, addr) {
		return
	}

	c.startCandidateRRC(ctx, currentAddr, addr)
}

func (c returnRoutabilityConn) useCandidatePath(
	rrcNegotiated bool,
	currentAddr, candidateAddr net.Addr,
) bool {
	switch c.conn.cidPathMigrationPolicy {
	case CIDPathMigrationReject:
		c.conn.log.Errorf(
			"rejected CID path migration from %s to %s: path migration is disabled",
			currentAddr,
			candidateAddr,
		)
	case CIDPathMigrationUnsafe:
		c.conn.lock.Lock()
		c.conn.rAddr = candidateAddr
		c.conn.lock.Unlock()
	case CIDPathMigrationRRC:
		if rrcNegotiated {
			return true
		}
		c.conn.log.Errorf(
			"rejected CID path migration from %s to %s: RRC was not negotiated",
			currentAddr,
			candidateAddr,
		)
	default:
		c.conn.log.Errorf("rejected CID path migration from %s to %s: invalid path migration policy", currentAddr, candidateAddr)
	}

	return false
}

func (c returnRoutabilityConn) startCandidateRRC(ctx context.Context, currentAddr, candidateAddr net.Addr) {
	cookie, ok, err := c.conn.rrc.Start(true, candidateAddr, currentAddr)
	if err == nil && ok {
		err = c.WriteRRC(ctx, candidateAddr, protocol.ReturnRoutabilityCheckPathChallenge, cookie)
		if err != nil {
			c.conn.rrc.Cancel(candidateAddr, cookie)
		}
	}
	if err != nil {
		c.conn.log.Debugf("unable to start return routability check: %v", err)
	}
}

func sameNetworkAddress(a, b net.Addr) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}

	return a.Network() == b.Network() && a.String() == b.String()
}

// cidDatagramRouter extracts connection IDs from incoming datagram payloads and
// uses them to route to the proper connection.
// NOTE: properly routing datagrams based on connection IDs requires using
// constant size connection IDs.
func cidDatagramRouter(size int) func([]byte) (string, bool) {
	return func(packet []byte) (string, bool) {
		pkts, _ := recordlayer.UnpackDatagram(packet, recordlayer.UnpackDatagramConfig{
			CIDLength:   size,
			CIDRequired: true,
		})
		if len(pkts) == 0 {
			return "", false
		}
		for _, pkt := range pkts {
			if protocol.IsDTLS13Ciphertext(protocol.ContentType(pkt[0])) {
				if pkt[0]&recordlayer.UnifiedHeaderCIDBit == 0 {
					continue
				}

				h := recordlayer.UnifiedHeader{ConnectionID: make([]byte, size)}
				if err := h.Unmarshal(pkt); err != nil {
					continue
				}

				return string(h.ConnectionID), true
			}

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
		firstRecordSize := h.MarshalSize() + int(h.ContentLen)
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
