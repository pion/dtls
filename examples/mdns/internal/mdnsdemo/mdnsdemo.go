// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package mdnsdemo carries a DTLS handshake in DNS-SD TXT updates.
package mdnsdemo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
	"github.com/pion/mdns/v2"
	"golang.org/x/net/ipv4"
)

const (
	serviceType          = "_pion-dtls._udp"
	clientInstancePrefix = "Pion DTLS client-"
	serverInstancePrefix = "Pion DTLS server-"
	serverInstance       = "Pion DTLS server"
	txtChunkSize         = 240
	maximumBatchSize     = 1200
)

var (
	errBatchTooLarge       = errors.New("DTLS batch is too large for this DNS-SD demo")
	errInvalidPartCount    = errors.New("invalid part count")
	errMissingPart         = errors.New("missing TXT part")
	errNoLoopbackInterface = errors.New("no active loopback interface")
	errNoPeerAddress       = errors.New("client has no IPv4 address or UDP port")
	errTrailingBatchData   = errors.New("trailing batch data")
)

type endpoint struct {
	name        string
	instance    string
	conn        *dtls.DetachedConn
	mdns        *mdns.Conn
	udp         *net.UDPConn
	peer        net.Addr
	done        <-chan struct{}
	onConnected func()
	report      func(error)
	mu          sync.Mutex
	sequence    uint64
	update      int
	lastSeq     uint64
	lastBatch   [][]byte
	localReady  bool
	peerReady   bool
	connected   bool
}

func (e *endpoint) start(ctx context.Context, firstEvent mdns.ServiceEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.conn.Start(ctx); err != nil {
		return fmt.Errorf("%s start DTLS: %w", e.name, err)
	}
	if err := e.drainEventsLocked(); err != nil {
		return err
	}

	return e.handleMDNSLocked(firstEvent)
}

func (e *endpoint) handleMDNS(event mdns.ServiceEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	select {
	case <-e.done:
		return nil
	default:
	}

	return e.handleMDNSLocked(event)
}

func (e *endpoint) handleMDNSLocked(event mdns.ServiceEvent) error {
	sequence, ready, datagrams, err := decodeBatch(event.Instance.Text)
	if err != nil {
		return fmt.Errorf("%s decode TXT from %q: %w", e.name, event.Instance.Instance, err)
	}
	if sequence == 0 {
		return nil
	}
	if sequence <= e.lastSeq {
		return nil
	}
	if ready {
		e.peerReady = true
	}

	if len(datagrams) != 0 {
		fmt.Printf("%s: receive handshake TXT (%d datagrams)\n", e.name, len(datagrams))
	}
	for _, datagram := range datagrams {
		if err = e.conn.HandleDatagram(datagram, e.peer); err != nil {
			return fmt.Errorf("%s handle DTLS datagram: %w", e.name, err)
		}
		if err = e.drainEventsLocked(); err != nil {
			return err
		}
	}
	e.lastSeq = sequence
	e.markConnectedLocked()

	return nil
}

func (e *endpoint) handleDatagram(datagram []byte, addr net.Addr) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	select {
	case <-e.done:
		return nil
	default:
	}

	if err := e.conn.HandleDatagram(datagram, addr); err != nil {
		return fmt.Errorf("%s handle DTLS datagram: %w", e.name, err)
	}

	return e.drainEventsLocked()
}

func (e *endpoint) write(data []byte) error { //nolint:contextcheck
	e.mu.Lock()
	defer e.mu.Unlock()

	n, err := e.conn.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}

	return e.drainEventsLocked()
}

func (e *endpoint) drainEventsLocked() error { //nolint:cyclop
	for {
		event := e.conn.NextEvent()
		switch event.Kind {
		case dtls.DetachedNoEvent:
			return nil
		case dtls.DetachedWriteDatagrams:
			if err := e.writeDatagrams(event.Datagrams, event.Addr); err != nil {
				return err
			}
		case dtls.DetachedApplicationData:
			fmt.Printf("%s: received %q\n", e.name, event.Data)
		case dtls.DetachedHandshakeDone:
			if !e.localReady {
				e.localReady = true
				if err := e.publishHandshakeBatchLocked(e.lastBatch); err != nil {
					return err
				}
				e.markConnectedLocked()
			}
		case dtls.DetachedClosed:
			return fmt.Errorf("%s DTLS closed: %w", e.name, event.Err)
		}
	}
}

func (e *endpoint) writeDatagrams(datagrams [][]byte, addr net.Addr) error {
	if e.connected {
		if addr == nil {
			addr = e.peer
		}
		for _, datagram := range datagrams {
			if _, err := e.udp.WriteTo(datagram, addr); err != nil {
				return fmt.Errorf("%s write UDP: %w", e.name, err)
			}
		}

		return nil
	}

	e.lastBatch = datagrams

	return e.publishHandshakeBatchLocked(datagrams)
}

func (e *endpoint) publishHandshakeBatchLocked(datagrams [][]byte) error {
	e.sequence++
	e.update++
	text, err := encodeBatch(e.sequence, e.localReady, datagrams)
	if err != nil {
		return fmt.Errorf("%s encode handshake batch: %w", e.name, err)
	}
	fmt.Printf(
		"%s: publish handshake TXT %d (%d datagrams, %d bytes, ready=%t)\n",
		e.name, e.update, len(datagrams), datagramBytes(datagrams), e.localReady,
	)
	if err = e.mdns.UpdateTXT(e.instance, serviceType, text); err != nil {
		return fmt.Errorf("%s publish handshake batch: %w", e.name, err)
	}

	return nil
}

func (e *endpoint) markConnectedLocked() {
	if e.connected || !e.localReady || !e.peerReady {
		return
	}
	e.connected = true
	fmt.Printf("%s: both handshakes complete; switched to UDP %s\n", e.name, e.udp.LocalAddr())
	e.onConnected()
}

func (e *endpoint) readUDP() {
	buffer := make([]byte, maximumBatchSize)
	for {
		n, addr, err := e.udp.ReadFrom(buffer)
		if err != nil {
			select {
			case <-e.done:
			default:
				e.report(fmt.Errorf("%s read UDP: %w", e.name, err))
			}

			return
		}
		if err = e.handleDatagram(buffer[:n], addr); err != nil {
			e.report(err)

			return
		}
	}
}

func (e *endpoint) watchEvents() {
	for {
		select {
		case <-e.conn.EventReady():
		case <-e.done:
			return
		}

		e.mu.Lock()
		select {
		case <-e.done:
			e.mu.Unlock()

			return
		default:
		}
		err := e.drainEventsLocked()
		e.mu.Unlock()
		if err != nil {
			e.report(err)

			return
		}
	}
}

func (e *endpoint) close() { //nolint:contextcheck
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = e.conn.Close()
	_ = e.drainEventsLocked()
}

type roleConfig struct {
	name         string
	instance     string
	peerInstance string
	isClient     bool
}

// RunClient discovers the server and starts an interactive DTLS session.
//
//nolint:cyclop,contextcheck
func RunClient(ctx context.Context) error {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	udpConn, err := listenUDP()
	if err != nil {
		return err
	}
	defer func() { _ = udpConn.Close() }()

	id := strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strconv.Itoa(udpConn.LocalAddr().(*net.UDPAddr).Port) //nolint:forcetypeassert
	role := roleConfig{
		name:         "client",
		instance:     clientInstancePrefix + id,
		peerInstance: serverInstancePrefix + id,
		isClient:     true,
	}
	mdnsConn, err := newMDNSConn(role, udpPort(udpConn))
	if err != nil {
		return err
	}
	defer func() { _ = mdnsConn.Close() }()

	completed := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	peerEvents := make(chan mdns.ServiceEvent, 16)
	report := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}
	mdnsConn.OnServiceDiscovered(func(event mdns.ServiceEvent) {
		if event.Instance.Instance == role.peerInstance {
			select {
			case peerEvents <- event:
			case <-sessionCtx.Done():
			}
		}
	})
	if err = mdnsConn.Browse(sessionCtx, serviceType); err != nil {
		return err
	}
	firstEvent, peer, err := awaitPeer(sessionCtx, peerEvents, errCh)
	if err != nil {
		return err
	}
	fmt.Printf("client: UDP %s; discovered server at %s via mDNS\n", udpConn.LocalAddr(), peer)

	conn, err := newDetachedConn(role, peer)
	if err != nil {
		return err
	}
	ep := &endpoint{
		name:        role.name,
		instance:    role.instance,
		conn:        conn,
		mdns:        mdnsConn,
		udp:         udpConn,
		peer:        peer,
		done:        sessionCtx.Done(),
		onConnected: func() { completed <- struct{}{} },
		report:      report,
		sequence:    uint64(time.Now().UnixNano()),
	}
	defer ep.close()
	if err = ep.start(sessionCtx, firstEvent); err != nil {
		return err
	}
	go ep.watchEvents()
	go ep.readUDP()
	go forwardMDNSEvents(sessionCtx, ep, peerEvents, report)

	select {
	case <-completed:
	case err = <-errCh:
		return err
	case <-sessionCtx.Done():
		return sessionCtx.Err()
	}

	return runInteractive(sessionCtx, role.name, ep, errCh)
}

// RunServer accepts and serves interactive DTLS sessions from multiple clients.
func RunServer(ctx context.Context) error {
	return runServer(ctx)
}

type serverSession struct {
	clientInstance string
	serverInstance string
	ep             *endpoint
	udp            *net.UDPConn
	cancel         context.CancelFunc
	connected      bool
}

type sessionFailure struct {
	session *serverSession
	err     error
}

//nolint:cyclop,contextcheck
func runServer(ctx context.Context) error {
	baseUDP, err := listenUDP()
	if err != nil {
		return err
	}
	defer func() { _ = baseUDP.Close() }()
	baseRole := roleConfig{name: "server", instance: serverInstance}
	mdnsConn, err := newMDNSConn(baseRole, udpPort(baseUDP))
	if err != nil {
		return err
	}
	defer func() { _ = mdnsConn.Close() }()

	peerEvents := make(chan mdns.ServiceEvent, 64)
	mdnsConn.OnServiceDiscovered(func(event mdns.ServiceEvent) {
		if strings.HasPrefix(event.Instance.Instance, clientInstancePrefix) {
			select {
			case peerEvents <- event:
			case <-ctx.Done():
			}
		}
	})
	if err = mdnsConn.Browse(ctx, serviceType); err != nil {
		return err
	}

	failures := make(chan sessionFailure, 16)
	connected := make(chan *serverSession, 16)
	sessions := make(map[string]*serverSession)
	input := make(chan string, 1)
	inputErr := make(chan error, 1)
	go readInput(input, inputErr)
	fmt.Println("server: accepting clients; typed messages are broadcast to every connected client")
	defer func() {
		for _, session := range sessions {
			closeServerSession(mdnsConn, session)
		}
	}()

	for {
		select {
		case event := <-peerEvents:
			instance := event.Instance.Instance
			if session := sessions[instance]; session != nil {
				if handleErr := session.ep.handleMDNS(event); handleErr != nil {
					fmt.Printf("server: client %q failed: %v\n", instance, handleErr)
					delete(sessions, instance)
					closeServerSession(mdnsConn, session)
				}

				continue
			}
			session, createErr := newServerSession(ctx, mdnsConn, event, connected, failures)
			if createErr != nil {
				fmt.Printf("server: reject client %q: %v\n", instance, createErr)

				continue
			}
			sessions[instance] = session
			fmt.Printf("server: discovered client %q at %s\n", instance, session.ep.peer)
		case session := <-connected:
			if sessions[session.clientInstance] == session {
				session.connected = true
				fmt.Printf("server: client %q connected\n", session.clientInstance)
			}
		case failure := <-failures:
			if sessions[failure.session.clientInstance] != failure.session {
				continue
			}
			fmt.Printf("server: client %q disconnected: %v\n", failure.session.clientInstance, failure.err)
			delete(sessions, failure.session.clientInstance)
			closeServerSession(mdnsConn, failure.session)
		case line := <-input:
			if line != "" {
				broadcast(sessions, line)
			}
		case inputReadErr := <-inputErr:
			return inputReadErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func newServerSession( //nolint:cyclop,contextcheck
	ctx context.Context,
	mdnsConn *mdns.Conn,
	event mdns.ServiceEvent,
	connected chan<- *serverSession,
	failures chan<- sessionFailure,
) (*serverSession, error) {
	if !event.Addr.Is4() || event.Instance.Port == 0 {
		return nil, errNoPeerAddress
	}
	peer := net.UDPAddrFromAddrPort(netip.AddrPortFrom(event.Addr, event.Instance.Port))
	udpConn, err := listenUDP()
	if err != nil {
		return nil, err
	}
	id := strings.TrimPrefix(event.Instance.Instance, clientInstancePrefix)
	role := roleConfig{
		name:         "server[" + id + "]",
		instance:     serverInstancePrefix + id,
		peerInstance: event.Instance.Instance,
	}
	if err = mdnsConn.Register(serviceInstance(role.instance, udpPort(udpConn))); err != nil {
		_ = udpConn.Close()

		return nil, err
	}
	conn, err := newDetachedConn(role, peer)
	if err != nil {
		mdnsConn.Unregister(role.instance, serviceType)
		_ = udpConn.Close()

		return nil, err
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	session := &serverSession{
		clientInstance: event.Instance.Instance,
		serverInstance: role.instance,
		udp:            udpConn,
		cancel:         cancel,
	}
	ep := &endpoint{
		name:     role.name,
		instance: role.instance,
		conn:     conn,
		mdns:     mdnsConn,
		udp:      udpConn,
		peer:     peer,
		done:     sessionCtx.Done(),
		onConnected: func() {
			select {
			case connected <- session:
			case <-sessionCtx.Done():
			}
		},
		sequence: uint64(time.Now().UnixNano()),
	}
	session.ep = ep
	ep.report = func(reportErr error) {
		select {
		case failures <- sessionFailure{session: session, err: reportErr}:
		case <-sessionCtx.Done():
		}
	}
	if err = ep.start(sessionCtx, event); err != nil {
		closeServerSession(mdnsConn, session) //nolint:contextcheck

		return nil, err
	}
	go ep.watchEvents()
	go ep.readUDP()

	return session, nil
}

func closeServerSession(mdnsConn *mdns.Conn, session *serverSession) { //nolint:contextcheck
	session.cancel()
	_ = session.udp.Close()
	session.ep.close()
	mdnsConn.Unregister(session.serverInstance, serviceType)
}

func broadcast(sessions map[string]*serverSession, line string) {
	sent := 0
	for _, session := range sessions {
		if !session.connected {
			continue
		}
		if err := session.ep.write([]byte(line)); err != nil {
			session.ep.report(err)

			continue
		}
		sent++
	}
	fmt.Printf("server: sent %q to %d client(s)\n", line, sent)
}

func forwardMDNSEvents(
	ctx context.Context,
	ep *endpoint,
	events <-chan mdns.ServiceEvent,
	report func(error),
) {
	for {
		select {
		case event := <-events:
			if err := ep.handleMDNS(event); err != nil {
				report(err)

				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func listenUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

func udpPort(conn *net.UDPConn) uint16 {
	return uint16(conn.LocalAddr().(*net.UDPAddr).Port) //nolint:forcetypeassert,gosec
}

func newDetachedConn(role roleConfig, peer net.Addr) (*dtls.DetachedConn, error) {
	pskCallback := func([]byte) ([]byte, error) { return []byte("pion-mdns-handshake"), nil }
	if role.isClient {
		return dtls.DetachedClient(peer,
			dtls.WithPSK(pskCallback),
			dtls.WithPSKIdentityHint([]byte("mdns-demo")),
			dtls.WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8),
			dtls.WithFlightInterval(2*time.Second),
		)
	}

	return dtls.DetachedServer(peer,
		dtls.WithPSK(pskCallback),
		dtls.WithCipherSuites(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8),
		dtls.WithFlightInterval(2*time.Second),
	)
}

//nolint:contextcheck
func runInteractive(
	ctx context.Context,
	name string,
	endpoint *endpoint,
	errCh <-chan error,
) error {
	fmt.Printf("%s: connected; type a message and press enter\n", name)

	input := make(chan string, 1)
	inputErr := make(chan error, 1)
	go readInput(input, inputErr)

	for {
		select {
		case line := <-input:
			if line == "" {
				continue
			}
			if err := endpoint.write([]byte(line)); err != nil {
				return err
			}
			fmt.Printf("%s: sent %q\n", name, line)
		case err := <-inputErr:
			return err
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func readInput(input chan<- string, inputErr chan<- error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, maximumBatchSize), maximumBatchSize)
	for scanner.Scan() {
		input <- scanner.Text()
	}
	inputErr <- scanner.Err()
}

func newMDNSConn(role roleConfig, port uint16) (*mdns.Conn, error) {
	loopback, err := loopbackInterface()
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp4", mdns.DefaultAddressIPv4)
	if err != nil {
		return nil, err
	}
	socket, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, err
	}
	packetConn := ipv4.NewPacketConn(socket)
	if err = packetConn.SetMulticastLoopback(true); err != nil {
		_ = socket.Close()

		return nil, err
	}

	conn, err := mdns.NewServer(
		packetConn,
		nil,
		mdns.WithName("dtls-mdns-"+role.name),
		mdns.WithIncludeLoopback(true),
		mdns.WithInterfaces(loopback),
		mdns.WithLocalAddress(net.IPv4(127, 0, 0, 1)),
		mdns.WithLocalNames("dtls-mdns-"+role.name+".local"),
		mdns.WithService(serviceInstance(role.instance, port)),
	)
	if err != nil {
		_ = socket.Close()

		return nil, err
	}

	return conn, nil
}

func serviceInstance(instance string, port uint16) mdns.ServiceInstance {
	return mdns.ServiceInstance{
		Instance: instance,
		Service:  serviceType,
		Port:     port,
		Text: []mdns.TXTEntry{
			mdns.NewTXTString("v", "1"),
			mdns.NewTXTString("seq", "0"),
			mdns.NewTXTString("ready", "0"),
			mdns.NewTXTString("parts", "0"),
		},
	}
}

func awaitPeer(
	ctx context.Context,
	events <-chan mdns.ServiceEvent,
	errCh <-chan error,
) (mdns.ServiceEvent, *net.UDPAddr, error) {
	for {
		select {
		case event := <-events:
			if event.Addr.Is4() && event.Instance.Port != 0 {
				return event, net.UDPAddrFromAddrPort(netip.AddrPortFrom(event.Addr, event.Instance.Port)), nil
			}
		case err := <-errCh:
			return mdns.ServiceEvent{}, nil, err
		case <-ctx.Done():
			return mdns.ServiceEvent{}, nil, ctx.Err()
		}
	}
}

func loopbackInterface() (net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			return iface, nil
		}
	}

	return net.Interface{}, errNoLoopbackInterface
}

func encodeBatch(sequence uint64, ready bool, datagrams [][]byte) ([]mdns.TXTEntry, error) {
	var payload bytes.Buffer
	if len(datagrams) > int(^uint16(0)) {
		return nil, errBatchTooLarge
	}
	_ = binary.Write(&payload, binary.BigEndian, uint16(len(datagrams))) //nolint:gosec
	for _, datagram := range datagrams {
		if len(datagram) > int(^uint16(0)) {
			return nil, errBatchTooLarge
		}
		_ = binary.Write(&payload, binary.BigEndian, uint16(len(datagram))) //nolint:gosec
		_, _ = payload.Write(datagram)
	}
	if payload.Len() > maximumBatchSize {
		return nil, fmt.Errorf("%w: %d bytes", errBatchTooLarge, payload.Len())
	}

	raw := payload.Bytes()
	partCount := (len(raw) + txtChunkSize - 1) / txtChunkSize
	text := []mdns.TXTEntry{
		mdns.NewTXTString("v", "1"),
		mdns.NewTXTString("seq", strconv.FormatUint(sequence, 10)),
		mdns.NewTXTString("ready", strconv.FormatBool(ready)),
		mdns.NewTXTString("parts", strconv.Itoa(partCount)),
	}
	for part := range partCount {
		start := part * txtChunkSize
		end := min(start+txtChunkSize, len(raw))
		text = append(text, mdns.NewTXTBinary(fmt.Sprintf("p%d", part), raw[start:end]))
	}

	return text, nil
}

func datagramBytes(datagrams [][]byte) int {
	var total int
	for _, datagram := range datagrams {
		total += len(datagram)
	}

	return total
}

func decodeBatch(text []mdns.TXTEntry) (uint64, bool, [][]byte, error) { //nolint:cyclop
	values := make(map[string][]byte, len(text))
	for _, entry := range text {
		values[strings.ToLower(entry.Key)] = entry.Value
	}
	if string(values["v"]) != "1" {
		return 0, false, nil, nil
	}

	sequence, err := strconv.ParseUint(string(values["seq"]), 10, 64)
	if err != nil {
		return 0, false, nil, fmt.Errorf("invalid sequence: %w", err)
	}
	ready := false
	if value, ok := values["ready"]; ok {
		ready, err = strconv.ParseBool(string(value))
		if err != nil {
			return 0, false, nil, fmt.Errorf("invalid ready state: %w", err)
		}
	}
	partCount, err := strconv.Atoi(string(values["parts"]))
	if err != nil || partCount < 0 {
		return 0, false, nil, errInvalidPartCount
	}
	if partCount == 0 {
		return sequence, ready, nil, nil
	}

	payload, err := joinTXTParts(values, partCount)
	if err != nil {
		return 0, false, nil, err
	}
	datagrams, err := decodeDatagrams(payload)
	if err != nil {
		return 0, false, nil, err
	}

	return sequence, ready, datagrams, nil
}

func joinTXTParts(values map[string][]byte, partCount int) ([]byte, error) {
	var payload bytes.Buffer
	for part := range partCount {
		chunk, ok := values[fmt.Sprintf("p%d", part)]
		if !ok {
			return nil, fmt.Errorf("%w: %d", errMissingPart, part)
		}
		_, _ = payload.Write(chunk)
	}

	return payload.Bytes(), nil
}

func decodeDatagrams(payload []byte) ([][]byte, error) {
	reader := bytes.NewReader(payload)
	var datagramCount uint16
	if err := binary.Read(reader, binary.BigEndian, &datagramCount); err != nil {
		return nil, err
	}
	datagrams := make([][]byte, 0, datagramCount)
	for range datagramCount {
		var size uint16
		if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
			return nil, err
		}
		datagram := make([]byte, size)
		if _, err := io.ReadFull(reader, datagram); err != nil {
			return nil, err
		}
		datagrams = append(datagrams, datagram)
	}
	if reader.Len() != 0 {
		return nil, errTrailingBatchData
	}

	return datagrams, nil
}
