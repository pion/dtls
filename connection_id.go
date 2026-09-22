// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	dtlshandshake "github.com/pion/dtls/v4/internal/handshake"
	idtlsnet "github.com/pion/dtls/v4/internal/net"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/pion/transport/v5/netctx"
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
	message := &protocol.ReturnRoutabilityCheck{MessageType: messageType, Cookie: cookie}
	raw, err := c.prepareRecord(message, addr)
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
	prepared.markPacketAsValid()
	var err error
	switch message.MessageType {
	case protocol.ReturnRoutabilityCheckPathChallenge:
		err = c.WriteRRC(ctx, addr, protocol.ReturnRoutabilityCheckPathResponse, message.Cookie)
	case protocol.ReturnRoutabilityCheckPathResponse:
		err = c.handleResponse(addr, message.Cookie)
	case protocol.ReturnRoutabilityCheckPathDrop:
		c.conn.rrc.Cancel(addr, message.Cookie)
	default:
		// Ignore unknown message types.
		// https://datatracker.ietf.org/doc/html/rfc9853#section-4
	}
	if err != nil {
		c.conn.log.Debugf("unable to handle return routability message: %v", err)
	}

	// A reachability probe does not request migration
	// https://www.rfc-editor.org/rfc/rfc9853.html#section-1
	return false, packetOutcome{}, nil
}

func (c returnRoutabilityConn) handleResponse(addr net.Addr, cookie [protocol.ReturnRoutabilityCheckCookieLength]byte) error {
	c.conn.lock.Lock()
	defer c.conn.lock.Unlock()
	if source, ok := addr.(pathAddress); ok {
		if source.path.acceptResponse(source.Addr, cookie) || source.path != source.path.transport.active {
			return nil
		}
	}
	if c.conn.rrc.HandleResponse(addr, cookie) {
		return c.conn.updateRemoteAddr(addr)
	}

	return nil
}

func (c returnRoutabilityConn) HandleCandidate(
	ctx context.Context,
	rrcNegotiated, hasCID, latest bool,
	addr net.Addr,
) {
	if !hasCID || !latest || !c.isActivePath(addr) {
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
	parsed, err := recordlayer.ParseRecord(record, size)
	if err != nil {
		return nil
	}

	return parsed.ConnectionID()
}

// registerLocalCID is called with c.lock held when preparing a handshake or importing a session.
func (c *Conn) registerLocalCID() error {
	if c.packetConn == nil {
		return nil
	}
	cid := dtlsstate.CommonState(c.state).LocalConnectionIDForInboundRecords()
	var ids *dtlsstate.CIDReceiveSet
	if state, ok := c.state.(*dtlsstate.State13); ok {
		ids = state.CID.Receive.IDs
	}
	if bytes.Equal(cid, c.registeredLocalCID) && ids == c.registeredReceiveCIDs {
		return nil
	}
	if err := c.packetConn.RegisterCID(cid); err != nil {
		return err
	}
	c.registeredLocalCID = bytes.Clone(cid)
	c.registeredReceiveCIDs = ids

	return nil
}

// acceptsInboundCID uses pre-negotiation DTLS 1.2 CID CID,
// or DTLS 1.3 CID set.
func (c *Conn) acceptsInboundCID(cid []byte) bool {
	if state, ok := c.state.(*dtlsstate.State13); ok && state.CID.Negotiated {
		return state.CID.Receive.IDs.Contains(cid)
	}

	return bytes.Equal(dtlsstate.CommonState(c.state).LocalConnectionIDForInboundRecords(), cid)
}

// reserveLocalCIDs reserves CID before publishing acceptance.
func (c *Conn) reserveLocalCIDs(cids [][]byte) ([][]byte, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.isConnectionClosed() {
		return nil, ErrConnClosed
	}

	state, ok := c.state.(*dtlsstate.State13)
	if !ok || !state.CID.Negotiated || !state.CID.Receive.CanSendNewConnectionID {
		return nil, dtlserrors.ErrUnexpectedPostHandshakeMessage
	}
	receive := &state.CID.Receive
	added, err := prepareLocalCIDs(receive, cids)
	if err != nil {
		return nil, err
	}
	if receive.IDs.Len()+len(added) > dtlsstate.MaxConnectionIDs {
		return nil, dtlserrors.ErrConnectionIDLimit
	}
	if c.packetConn != nil {
		if err := c.packetConn.RegisterCIDs(added); err != nil {
			return nil, err
		}
	}
	for _, cid := range added {
		receive.IDs.Add(cid)
	}

	return added, nil
}

// prepareLocalCIDs validates and copies new IDs.
func prepareLocalCIDs(receive *dtlsstate.CIDReceiveState, cids [][]byte) ([][]byte, error) {
	seen := make(map[string]bool, len(cids))
	var added [][]byte
	for _, cid := range cids {
		if len(cid) != receive.Length {
			return nil, dtlserrors.ErrInvalidConnectionIDLength
		}
		key := string(cid)
		if seen[key] || receive.IDs.Contains(cid) {
			continue
		}
		seen[key] = true
		added = append(added, bytes.Clone(cid))
	}

	return added, nil
}

func (c handshakeConn) ReserveLocalCIDs(cids [][]byte) ([][]byte, error) {
	return c.conn.reserveLocalCIDs(cids)
}

func (c handshakeConn) RemoveLocalCIDs(cids [][]byte) {
	c.conn.removeLocalCIDs(cids)
}

// CommitPeerConnectionIDs serializes selection with every protected writer.
func (c handshakeConn) CommitPeerConnectionIDs(message *handshake.MessageNewConnectionID) error {
	c.conn.writeLock.Lock()
	defer c.conn.writeLock.Unlock()
	c.conn.lock.Lock()
	defer c.conn.lock.Unlock()
	if c.conn.isConnectionClosed() {
		return ErrConnClosed
	}
	state, ok := c.conn.state.(*dtlsstate.State13)
	if !ok {
		return dtlserrors.ErrInvalidProtocolVersionState
	}
	send := &state.CID.Send
	cids := message.CIDs
	if message.Usage == handshake.ConnectionIDImmediate {
		if len(cids) == 0 {
			return dtlserrors.ErrInvalidCIDFormat
		}
		send.Active = bytes.Clone(cids[0])
		send.UseCID = len(send.Active) != 0
		cids = cids[1:]
		send.Spares = slices.DeleteFunc(send.Spares, func(cid []byte) bool {
			return bytes.Equal(cid, send.Active)
		})
	}
	for _, cid := range cids {
		if len(send.Spares) == dtlsstate.MaxConnectionIDs {
			break
		}
		if bytes.Equal(cid, send.Active) || slices.ContainsFunc(send.Spares, func(spare []byte) bool {
			return bytes.Equal(cid, spare)
		}) {
			continue
		}
		send.Spares = append(send.Spares, bytes.Clone(cid))
	}

	return nil
}

func (c *Conn) clearConnectionIDs() {
	c.lock.Lock()
	defer c.lock.Unlock()
	if state, ok := c.state.(*dtlsstate.State13); ok {
		state.CID.Receive.IDs.Clear()
		state.CID.Send.Spares = nil
		clear(c.pendingCIDACKs)
	}
}

// removeLocalCIDs removes retired or never-advertised IDs.
func (c *Conn) removeLocalCIDs(cids [][]byte) {
	c.lock.Lock()
	defer c.lock.Unlock()
	state, ok := c.state.(*dtlsstate.State13)
	if !ok || state.CID.Receive.IDs == nil {
		return
	}
	for _, cid := range cids {
		state.CID.Receive.IDs.Remove(cid)
		if c.packetConn != nil {
			c.packetConn.UnregisterCID(cid)
		}
	}
}

func (c *Conn) pendingCIDNegotiation() bool {
	common := dtlsstate.CommonState(c.state)

	return common.ConnectionIDPending() && len(common.LocalConnectionIDForInboundRecords()) > 0 && common.LocalVersion != protocol.Version1_2
}

// updateRemoteAddr is called only after the migration policy accepts a path.
// Sending an RRC probe must not move the listener's address route.
func (c *Conn) updateRemoteAddr(addr net.Addr) error {
	if source, ok := addr.(pathAddress); ok {
		addr = source.Addr
	}
	if c.packetConn != nil {
		if err := c.packetConn.SetRemoteAddr(addr); err != nil {
			return err
		}
	}
	c.rAddr = addr

	return nil
}

func (c *Conn) takePendingACKs() []protocol.RecordNumber {
	c.lock.Lock()
	defer c.lock.Unlock()

	records := c.pendingACKs
	c.pendingACKs = nil
	for number, sequence := range c.pendingCIDACKs {
		if int(sequence) < dtlsstate.HandshakeRecvSequence(c.state) {
			records = append(records, number)
			delete(c.pendingCIDACKs, number)
		}
	}

	return records
}

func (c *Conn) queueHandshakeACK(content []byte, number protocol.RecordNumber) {
	lastCIDSequence := -1
	for len(content) != 0 {
		var header handshake.Header
		if err := header.Unmarshal(content); err != nil {
			return
		}
		if header.Type == handshake.TypeNewConnectionID {
			lastCIDSequence = max(lastCIDSequence, int(header.MessageSequence))
		}
		content = content[handshake.HeaderLength+int(header.FragmentLength):]
	}
	if lastCIDSequence < dtlsstate.HandshakeRecvSequence(c.state) {
		c.pendingACKs = append(c.pendingACKs, number)

		return
	}
	const maxPendingCIDACKs = 256
	if len(c.pendingCIDACKs) == maxPendingCIDACKs {
		return
	}
	if c.pendingCIDACKs == nil {
		c.pendingCIDACKs = make(map[protocol.RecordNumber]uint16)
	}
	c.pendingCIDACKs[number] = uint16(lastCIDSequence) //nolint:gosec // copied from a uint16 message sequence.
}

// Path is a local transport to the connection's current peer. Obtain one with
// [Conn.AddPath], validate it with [Path.Probe], then use [Path.Switch] to move
// application writes. With CIDPathMigrationUnsafe, Switch skips validation.
// All methods may be called concurrently.
type Path struct {
	*pathSocket
}

// pathSocket owns one socket and its receiving goroutine.
type pathSocket struct {
	transport   *pathTransport
	socket      netctx.PacketConn
	remote      net.Addr
	lifetime    context.Context //nolint:containedctx
	cancel      context.CancelCauseFunc
	closeSocket func() error

	cid       []byte
	probe     *pathProbe
	validated bool
}

type pathProbe struct {
	done    chan struct{}
	cookies [][protocol.ReturnRoutabilityCheckCookieLength]byte
	expires time.Time
}

// AddPath adds a dedicated, unconnected packet socket to an established DTLS 1.3
// connection with a nonempty peer CID. CIDPathMigrationRRC requires negotiated
// RRC, CIDPathMigrationUnsafe allows switching without validation.
// The peer address stays unchanged. On success, the connection owns socket and
// closes it when the path or connection closes.
func (c *Conn) AddPath(socket net.PacketConn) (*Path, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.isConnectionClosed() {
		return nil, ErrConnClosed
	}
	if !c.isHandshakeCompletedSuccessfully() {
		return nil, dtlserrors.ErrHandshakeInProgress
	}
	transport, supported := c.nextConn.(*pathTransport)
	if !supported || !c.canMigratePath() {
		return nil, errPathMigrationUnavailable
	}
	if socket == nil {
		return nil, dtlserrors.ErrNilNextConn
	}
	for path := range transport.paths {
		if sameNetworkAddress(path.socket.LocalAddr(), socket.LocalAddr()) {
			return nil, errPathInUse
		}
	}
	path := transport.add(netctx.NewPacketConn(socket))
	go path.read()

	return &Path{pathSocket: path}, nil
}

// canMigratePath is called with c.lock held.
func (c *Conn) canMigratePath() bool {
	state, ok := c.state.(*dtlsstate.State13)

	return ok && state.CID.Send.UseCID &&
		(c.cidPathMigrationPolicy == CIDPathMigrationUnsafe || state.RRCNegotiated)
}

// Probe checks reachability using RRC, reserving a peer CID on the first call.
// Each call performs a new check and honors ctx and the write deadline.
// Probe requires CIDPathMigrationRRC, it is unavailable in unsafe mode.
// RRC validation takes at most one second after obtaining a CID. A failed check
// leaves application writes on the current path and requires a successful retry
// before switching.
//
//nolint:contextcheck
func (p *Path) Probe(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conn := p.transport.conn
	if conn.writeDeadline.Err() != nil {
		return dtlserrors.ErrDeadlineExceeded
	}
	operationCtx, cancel := conn.contextWithCloseAndWriteDeadline(ctx)
	defer cancel()
	detach := context.AfterFunc(p.lifetime, cancel)
	defer detach()

	probe, err := p.beginProbe()
	if err != nil {
		return err
	}
	if err = p.obtainCID(operationCtx); err == nil {
		err = p.probePath(operationCtx, probe)
	}

	return conn.normalizeKeyUpdateError(ctx, operationCtx, p.finishProbe(err))
}

func (p *Path) beginProbe() (*pathProbe, error) {
	conn := p.transport.conn
	conn.lock.Lock()
	defer conn.lock.Unlock()
	if conn.isConnectionClosed() {
		return nil, ErrConnClosed
	}
	if err := context.Cause(p.lifetime); err != nil {
		return nil, err
	}
	if conn.cidPathMigrationPolicy != CIDPathMigrationRRC {
		return nil, errPathMigrationUnavailable
	}
	if p.probe != nil {
		return nil, errPathInUse
	}
	if !sameNetworkAddress(p.remote, conn.rAddr) {
		return nil, errPathNotValidated
	}
	p.validated = false
	p.probe = &pathProbe{done: make(chan struct{})}

	return p.probe, nil
}

func (p *Path) finishProbe(err error) error {
	p.transport.conn.lock.Lock()
	defer p.transport.conn.lock.Unlock()
	select {
	case <-p.probe.done:
		err = nil
	default:
	}
	p.probe = nil
	if cause := context.Cause(p.lifetime); cause != nil {
		err = cause
	}
	p.validated = err == nil

	return err
}

func (p *Path) obtainCID(ctx context.Context) error {
	select {
	case p.transport.cidRequest <- struct{}{}:
		defer func() { <-p.transport.cidRequest }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if p.takeCID() {
		return nil
	}
	updater, ok := p.transport.conn.fsm.(dtlshandshake.ConnectionIDUpdater)
	if !ok {
		return dtlserrors.ErrNotImplemented
	}
	if err := updater.RequestConnectionIDs(ctx, 1); err != nil {
		return err
	}
	if !p.takeCID() {
		return errNoConnectionID
	}

	return nil
}

func (p *Path) takeCID() bool {
	conn := p.transport.conn
	conn.lock.Lock()
	defer conn.lock.Unlock()
	if len(p.cid) != 0 {
		return true
	}
	state, ok := conn.state.(*dtlsstate.State13)
	if !ok || conn.isConnectionClosed() {
		return false
	}
	p.transport.usedCIDs[string(state.CID.Send.Active)] = true
	for len(state.CID.Send.Spares) != 0 {
		cid := state.CID.Send.Spares[0]
		state.CID.Send.Spares = state.CID.Send.Spares[1:]
		if len(cid) == 0 || p.transport.usedCIDs[string(cid)] {
			continue
		}
		p.transport.usedCIDs[string(cid)] = true
		p.cid = cid

		return true
	}

	return false
}

func (p *Path) probePath(ctx context.Context, probe *pathProbe) error {
	// Use one second when no RTT estimate is available.
	// https://www.rfc-editor.org/rfc/rfc9853.html#section-5.5
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn := p.transport.conn
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		var cookie [protocol.ReturnRoutabilityCheckCookieLength]byte
		if _, err := rand.Read(cookie[:]); err != nil {
			return err
		}
		conn.lock.Lock()
		probe.expires, _ = ctx.Deadline()
		probe.cookies = append(probe.cookies, cookie)
		conn.lock.Unlock()
		if err := (returnRoutabilityConn{conn: conn}).WriteRRC(ctx, pathAddress{Addr: p.remote, path: p.pathSocket}, protocol.ReturnRoutabilityCheckPathChallenge, cookie); err != nil {
			return err
		}
		select {
		case <-probe.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}

	return ctx.Err()
}

// Switch makes this validated path the connection's application write path.
// It changes LocalAddr and the outgoing CID atomically with respect to writers.
// Existing sockets keep receiving until closed. The peer address must still
// match the address validated by Probe.
// With CIDPathMigrationUnsafe, Switch skips validation and reuses the active CID
// for a new path.
func (p *Path) Switch() error {
	conn := p.transport.conn
	conn.writeLock.Lock()
	defer conn.writeLock.Unlock()
	conn.lock.Lock()
	defer conn.lock.Unlock()
	if conn.isConnectionClosed() {
		return ErrConnClosed
	}
	if err := context.Cause(p.lifetime); err != nil {
		return err
	}
	if (!p.validated && conn.cidPathMigrationPolicy != CIDPathMigrationUnsafe) || !sameNetworkAddress(p.remote, conn.rAddr) {
		return errPathNotValidated
	}
	if p.transport.active == p.pathSocket {
		return nil
	}
	state, ok := conn.state.(*dtlsstate.State13)
	if !ok || !state.CID.Send.UseCID {
		return errPathMigrationUnavailable
	}
	p.transport.active.cid = bytes.Clone(state.CID.Send.Active)
	if len(p.cid) == 0 {
		p.cid = bytes.Clone(state.CID.Send.Active)
	}
	state.CID.Send.Active = bytes.Clone(p.cid)
	p.transport.active = p.pathSocket
	conn.rrc.Reset()

	return nil
}

// Close releases an inactive path's socket and cancels any pending Probe.
// Closing the active path returns an error.
func (p *Path) Close() error {
	conn := p.transport.conn
	conn.lock.Lock()
	if p.transport.active == p.pathSocket && !conn.isConnectionClosed() {
		conn.lock.Unlock()

		return errPathInUse
	}
	p.cancel(net.ErrClosed)
	delete(p.transport.paths, p.pathSocket)
	conn.lock.Unlock()

	return p.closeSocket()
}

// pathAddress carries the receiving socket through record processing and queued
// records.
type pathAddress struct {
	net.Addr
	path *pathSocket
}

type pathDatagram struct {
	buffer *[]byte
	size   int
	addr   pathAddress
	err    error
}

type pathTransport struct {
	conn       *Conn
	start      func()
	incoming   chan pathDatagram
	cidRequest chan struct{}
	// Protected by conn.lock.
	active   *pathSocket
	paths    map[*pathSocket]struct{}
	usedCIDs map[string]bool
}

func newPathTransport(conn *Conn, socket netctx.PacketConn) *pathTransport {
	transport := &pathTransport{
		conn: conn, incoming: make(chan pathDatagram, 16), cidRequest: make(chan struct{}, 1),
		paths: make(map[*pathSocket]struct{}), usedCIDs: make(map[string]bool),
	}
	initial := transport.add(socket)
	transport.active = initial
	transport.start = sync.OnceFunc(func() { go initial.read() })

	return transport
}

// add is called with conn.lock held, or during connection construction.
func (t *pathTransport) add(socket netctx.PacketConn) *pathSocket {
	lifetime, cancel := context.WithCancelCause(t.conn.closed)
	path := &pathSocket{transport: t, socket: socket, remote: t.conn.rAddr, lifetime: lifetime, cancel: cancel, closeSocket: sync.OnceValue(socket.Close)}
	t.paths[path] = struct{}{}

	return path
}

func (p *pathSocket) read() {
	conn := p.transport.conn
	for {
		buffer, ok := conn.readBufferPool.Get().(*[]byte)
		if !ok {
			return
		}
		n, addr, err := p.socket.Conn().ReadFrom(*buffer)
		packet := pathDatagram{buffer: buffer, size: n, addr: pathAddress{Addr: addr, path: p}, err: err}
		select {
		case p.transport.incoming <- packet:
		case <-p.lifetime.Done():
			conn.readBufferPool.Put(buffer)

			return
		}
		if err != nil && !idtlsnet.IsShortBuffer(err) {
			conn.lock.RLock()
			if p != p.transport.active || conn.classifyReadLoopError(netError(err)) != readLoopDeliverAndContinue {
				p.cancel(err)
				conn.lock.RUnlock()

				return
			}
			conn.lock.RUnlock()
		}
	}
}

func (t *pathTransport) ReadFromContext(ctx context.Context, buffer []byte) (int, net.Addr, error) {
	t.start()
	for {
		select {
		case packet := <-t.incoming:
			n := copy(buffer, (*packet.buffer)[:packet.size])
			t.conn.readBufferPool.Put(packet.buffer)
			t.conn.lock.RLock()
			path := packet.addr.path
			accept := path == t.active || (packet.err == nil && path.lifetime.Err() == nil && sameNetworkAddress(packet.addr.Addr, path.remote))
			t.conn.lock.RUnlock()
			if !accept {
				continue
			}

			return n, packet.addr, packet.err
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		}
	}
}

func (t *pathTransport) WriteToContext(ctx context.Context, packet []byte, addr net.Addr) (int, error) {
	t.conn.lock.RLock()
	path := t.active
	if source, ok := addr.(pathAddress); ok {
		path, addr = source.path, source.Addr
	}
	t.conn.lock.RUnlock()

	return path.socket.WriteToContext(ctx, packet, addr)
}

func (t *pathTransport) LocalAddr() net.Addr {
	return t.Conn().LocalAddr()
}

func (t *pathTransport) Conn() net.PacketConn {
	t.conn.lock.RLock()
	defer t.conn.lock.RUnlock()

	return t.active.socket.Conn()
}

func (t *pathTransport) Close() error {
	t.conn.lock.Lock()
	paths := t.paths
	t.paths = nil
	t.conn.lock.Unlock()
	var err error
	for path := range paths {
		path.cancel(ErrConnClosed)
		err = errors.Join(err, path.closeSocket())
	}

	return err
}

func (c returnRoutabilityConn) prepareRecord(message *protocol.ReturnRoutabilityCheck, addr net.Addr) ([]byte, error) {
	packet := &dtlsflight.Outbound{Epoch: dtlsstate.CommonState(c.conn.state).LocalEpoch(), Content: message, Protection: dtlsflight.ProtectionCiphertext}
	source, tagged := addr.(pathAddress)
	if !tagged || source.path == source.path.transport.active {
		return c.conn.prepareRecord(packet)
	}
	path := source.path
	if err := context.Cause(path.lifetime); err != nil {
		return nil, err
	}
	if len(path.cid) == 0 {
		return nil, errNoConnectionID
	}
	state, ok := c.conn.state.(*dtlsstate.State13)
	if !ok || !state.CID.Send.UseCID {
		return nil, errPathMigrationUnavailable
	}
	if message.MessageType == protocol.ReturnRoutabilityCheckPathResponse {
		// This socket is not the preferred path.
		// https://www.rfc-editor.org/rfc/rfc9853.html#section-5.4
		message.MessageType = protocol.ReturnRoutabilityCheckPathDrop
	}
	active := state.CID.Send.Active
	state.CID.Send.Active = path.cid
	defer func() { state.CID.Send.Active = active }()

	return c.conn.prepareRecord(packet)
}

func (c returnRoutabilityConn) isActivePath(addr net.Addr) bool {
	c.conn.lock.RLock()
	defer c.conn.lock.RUnlock()
	source, tagged := addr.(pathAddress)

	return !tagged || source.path == source.path.transport.active
}

// acceptResponse is called with conn.lock held, after record authentication.
func (p *pathSocket) acceptResponse(addr net.Addr, cookie [protocol.ReturnRoutabilityCheckCookieLength]byte) bool {
	probe := p.probe
	if probe == nil || p.lifetime.Err() != nil || !sameNetworkAddress(addr, p.remote) {
		return false
	}
	if !time.Now().Before(probe.expires) || !slices.Contains(probe.cookies, cookie) {
		return false
	}
	select {
	case <-probe.done:
	default:
		close(probe.done)
	}

	return true
}
