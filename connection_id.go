// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
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

	if c.conn.detached != nil {
		c.conn.detached.publishDatagrams([][]byte{raw}, addr)
	} else {
		_, err = c.conn.nextConn.WriteToContext(ctx, raw, addr)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) && c.conn.isConnectionClosed() {
			return ErrConnClosed
		}

		return netError(err)
	}

	return nil
}

func (c returnRoutabilityConn) HandleRecord(ctx context.Context, message *protocol.ReturnRoutabilityCheck, prepared incomingPacketState, addr net.Addr) (bool, packetOutcome, error) {
	if c.conn.cidPathMigrationPolicy != CIDPathMigrationRRC || prepared.number.Epoch == 0 || !dtlsstate.CommonState(c.conn.state).RRCNegotiated {
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
			err = c.conn.updateRemoteAddr(addr)
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
		if err := c.conn.updateRemoteAddr(candidateAddr); err != nil {
			c.conn.log.Debugf("unable to move address route: %v", err)
		}
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
			if cid := recordConnectionID(pkt, size); len(cid) > 0 {
				return string(cid), true
			}
		}

		return "", false
	}
}

// recordConnectionID returns CID bytes borrowed from an already scanned record.
func recordConnectionID(record []byte, size int) []byte {
	if size == 0 {
		return nil
	}
	if protocol.IsDTLS13Ciphertext(protocol.ContentType(record[0])) {
		if record[0]&recordlayer.UnifiedHeaderCIDBit != 0 {
			return record[1 : 1+size]
		}
	} else if protocol.ContentType(record[0]) == protocol.ContentTypeConnectionID {
		const cidOffset = recordlayer.FixedHeaderSize - 2

		return record[cidOffset : cidOffset+size]
	}

	return nil
}

// registerLocalCID is called with c.lock held when preparing a handshake or importing a session.
func (c *Conn) registerLocalCID() error {
	if c.packetConn == nil {
		return nil
	}
	cid := dtlsstate.CommonState(c.state).LocalConnectionIDForInboundRecords()
	if bytes.Equal(cid, c.registeredLocalCID) {
		return nil
	}
	if err := c.packetConn.RegisterCID(cid); err != nil {
		return err
	}
	c.registeredLocalCID = bytes.Clone(cid)

	return nil
}

func (c *Conn) pendingCIDNegotiation() bool {
	common := dtlsstate.CommonState(c.state)

	return common.ConnectionIDPending() && len(common.LocalConnectionIDForInboundRecords()) > 0 && common.LocalVersion != protocol.Version1_2
}

// updateRemoteAddr is called only after the migration policy accepts a path.
// Sending an RRC probe must not move the listener's address route.
func (c *Conn) updateRemoteAddr(addr net.Addr) error {
	if c.packetConn != nil {
		if err := c.packetConn.SetRemoteAddr(addr); err != nil {
			return err
		}
	}
	c.rAddr = addr

	return nil
}
