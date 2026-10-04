// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main demonstrates DTLS resumption and optional client 0-RTT.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"golang.org/x/term"
)

const (
	earlyLimit      = 4096
	serverAddress   = "127.0.0.1:4444"
	certificatePath = "server.crt"
	keyPath         = "server.key"
	ticketPath      = "session.enc"
)

var (
	errCertificate = errors.New("CA file contains no certificates")
	errPassphrase  = errors.New("session-file passphrase must not be empty")
	errEarlySize   = errors.New("early text exceeds 4096 bytes")
)

type endpoint struct {
	conn                    *dtls.DetachedConn
	udp                     *net.UDPConn
	server, ready, accepted bool
	early                   string
	cancel                  context.CancelFunc
	store                   *connectionStore
	pending                 [][]byte
}

func main() {
	server := flag.Bool("server", false, "run the server")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)

	var err error
	if *server {
		err = serve(ctx)
	} else {
		err = client(ctx)
	}
	stop()
	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(ctx context.Context) error {
	certificate, err := loadServerCertificate(certificatePath, keyPath)
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", serverAddress)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer udp.Close() //nolint:errcheck
	store := newStore()
	fmt.Println("Listening on", udp.LocalAddr(), "(handles one client at a time)")
	for ctx.Err() == nil {
		data, peer, err := readDatagram(udp)
		if isTimeout(err) {
			continue
		}
		if err != nil {
			return err
		}
		peerStore := &connectionStore{sessionStore: store}
		conn, err := dtls.DetachedServer(peer,
			dtls.WithCertificates(certificate), dtls.WithSessionStore(peerStore, dtls.WithMaxEarlyDataSize(earlyLimit)),
			dtls.WithMinVersion(protocol.Version1_3), dtls.WithMaxVersion(protocol.Version1_3),
			dtls.WithInsecureSkipVerifyHello(true)) // HRR cookies prevent 0-RTT. Only do this if you want to do 0-RTT and have another way to validate the paths.
		if err != nil {
			return err
		}
		ep := &endpoint{conn: conn, udp: udp, server: true, store: peerStore}
		if err = ep.start(ctx, data, peer); err == nil {
			err = ep.run(ctx, peer, nil)
		}
		ep.close() //nolint:contextcheck
		reportPeerError(err)
	}

	return ctx.Err()
}

func client(ctx context.Context) (result error) {
	password, err := readPassphrase()
	if err != nil {
		return err
	}
	store := newStore()
	saved, err := store.load(ticketPath, password)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(os.Stdin)
	early := ""
	if saved {
		fmt.Print("Saved session found. Optional 0-RTT text (Enter = normal resumption): ")
		if scanner.Scan() {
			early = scanner.Text()
		}
		if err = scanner.Err(); err != nil {
			return err
		}
	}
	if len(early) > earlyLimit {
		return errEarlySize
	}
	conn, udp, peer, err := dial(store, early != "")
	if err != nil {
		return err
	}
	defer udp.Close() //nolint:errcheck
	ep := &endpoint{conn: conn, udp: udp, early: early}
	defer func() { //nolint:contextcheck
		ep.close()
		saveErr := store.save(ticketPath, password)
		result = errors.Join(result, saveErr)
		if saveErr == nil {
			fmt.Println("Session saved:", ticketPath)
		}
	}()
	if err = ep.start(ctx, nil, peer); err != nil {
		return err
	}
	lines := make(chan string)
	go readLines(ctx, scanner, lines)
	fmt.Println("Type text after the handshake; /quit or ctrl+C to close and save the session")

	return clientResult(ep.run(ctx, peer, lines))
}

func dial(store *sessionStore, early bool) (*dtls.DetachedConn, *net.UDPConn, net.Addr, error) {
	pem, err := os.ReadFile(certificatePath)
	if err != nil {
		return nil, nil, nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, nil, nil, errCertificate
	}
	peer, err := net.ResolveUDPAddr("udp", serverAddress)
	if err != nil {
		return nil, nil, nil, err
	}
	udp, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, nil, nil, err
	}
	limit := uint32(0)
	if early {
		limit = earlyLimit
	}
	conn, err := dtls.DetachedClient(peer, dtls.WithRootCAs(roots), dtls.WithServerName("localhost"),
		dtls.WithSessionStore(store, dtls.WithMaxEarlyDataSize(limit)),
		dtls.WithMinVersion(protocol.Version1_3), dtls.WithMaxVersion(protocol.Version1_3))
	if err != nil {
		_ = udp.Close()
	}

	return conn, udp, peer, err
}

func (e *endpoint) start(ctx context.Context, first []byte, peer net.Addr) error {
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	e.cancel = cancel
	if err := e.conn.Start(handshakeCtx); err != nil {
		cancel()

		return err
	}
	if first != nil {
		return e.conn.HandleDatagram(first, peer)
	}

	return nil
}

func readLines(ctx context.Context, scanner *bufio.Scanner, lines chan<- string) {
	defer close(lines)
	for scanner.Scan() {
		select {
		case lines <- scanner.Text():
		case <-ctx.Done():
			return
		}
	}
}

func readDatagram(udp *net.UDPConn) ([]byte, net.Addr, error) {
	if err := udp.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return nil, nil, err
	}
	buffer := make([]byte, 65535)
	n, peer, err := udp.ReadFrom(buffer)

	return buffer[:n], peer, err
}

func isTimeout(err error) bool {
	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}

func (e *endpoint) run(ctx context.Context, peer net.Addr, lines <-chan string) error {
	for ctx.Err() == nil {
		if err := e.drain(); err != nil { //nolint:contextcheck
			return err
		}
		select {
		case text, ok := <-lines:
			if !ok || strings.TrimSpace(text) == "/quit" {
				return nil
			}
			if !e.ready {
				fmt.Println("Handshake pending; try again.")

				continue
			}
			if _, err := e.conn.Write([]byte(text)); err != nil { //nolint:contextcheck
				return err
			}

			continue
		default:
		}
		if err := e.receive(peer); err != nil {
			return err
		}
	}

	return ctx.Err()
}

func (e *endpoint) drain() error {
	for event := e.conn.NextEvent(); event.Kind != dtls.DetachedNoEvent; event = e.conn.NextEvent() {
		if err := e.handleEvent(event); err != nil {
			return err
		}
	}

	return nil
}

func (e *endpoint) handleEvent(event dtls.DetachedEvent) error {
	switch event.Kind {
	case dtls.DetachedWriteDatagrams:
		return e.sendDatagrams(event)
	case dtls.DetachedEarlyDataReady:
		if _, err := e.conn.WriteEarlyData([]byte(e.early)); err != nil {
			return err
		}

	case dtls.DetachedEarlyDataAccepted:
		e.accepted = true
		fmt.Println("0-RTT accepted")
	case dtls.DetachedEarlyDataRejected:
		fmt.Println("0-RTT rejected. will be sent after the handshake")
	case dtls.DetachedHandshakeDone:
		return e.handshakeDone()
	case dtls.DetachedApplicationData:
		return e.applicationData(event.Data)
	case dtls.DetachedClosed:
		return closedError(event.Err)
	default:
	}

	return nil
}

func (e *endpoint) handshakeDone() error {
	e.ready = true
	e.cancel()
	if e.server {
		e.accepted = e.store.accepted.Load()
	}
	state, _ := e.conn.ConnectionState()
	mode := "full handshake"
	if len(state.IdentityHint) != 0 {
		mode = "session resumption"
	}
	if e.accepted {
		mode += " with early data"
	}
	fmt.Println(mode)
	if e.server {
		return e.flushEarlyEcho()
	}
	if !e.server && e.early != "" && !e.accepted {
		_, err := e.conn.Write([]byte(e.early))

		return err
	}

	return nil
}

func (e *endpoint) applicationData(data []byte) error {
	if !e.ready {
		e.accepted = true
		fmt.Printf("0-RTT received: %q\n", data)
		// Normal Write is available after handshake completion.
		e.pending = append(e.pending, data)

		return nil
	}
	fmt.Printf("Received: %q\n", data)
	if e.server {
		_, err := e.conn.Write(data)

		return err
	}

	return nil
}

func (e *endpoint) close() {
	if e.cancel != nil {
		defer e.cancel()
	}
	_ = e.conn.Close()
	_ = e.drain()
}

func reportPeerError(err error) {
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, dtls.ErrConnClosed) {
		fmt.Println("Peer:", err)
	}
}

func (e *endpoint) receive(peer net.Addr) error {
	data, from, err := readDatagram(e.udp)
	if isTimeout(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if from.String() != peer.String() {
		return nil
	}

	return e.conn.HandleDatagram(data, from)
}

func (e *endpoint) sendDatagrams(event dtls.DetachedEvent) error {
	for _, data := range event.Datagrams {
		if _, err := e.udp.WriteTo(data, event.Addr); err != nil {
			return err
		}
	}

	return nil
}

func (e *endpoint) flushEarlyEcho() error {
	for _, data := range e.pending {
		if _, err := e.conn.Write(data); err != nil {
			return err
		}
	}
	e.pending = nil

	return nil
}

func closedError(err error) error {
	if err == nil || errors.Is(err, dtls.ErrConnClosed) {
		return io.EOF
	}

	return err
}

func clientResult(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) || errors.Is(err, dtls.ErrConnClosed) {
		return nil
	}

	return err
}

// only generate an identity when both files are missing.
func loadServerCertificate(certPath, keyPath string) (tls.Certificate, error) {
	certificate, loadErr := tls.LoadX509KeyPair(certPath, keyPath)
	if loadErr == nil {
		return certificate, nil
	}
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			return tls.Certificate{}, loadErr
		}
	}
	certificate, err := selfsign.GenerateSelfSignedWithDNS("localhost")
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err = writeIdentityFile(keyPath, &pem.Block{Type: "PRIVATE KEY", Bytes: key}); err != nil {
		return tls.Certificate{}, err
	}
	if err = writeIdentityFile(certPath, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}); err != nil {
		return tls.Certificate{}, errors.Join(err, os.Remove(keyPath))
	}
	fmt.Println("Generated localhost identity:", certPath, keyPath)

	return certificate, nil
}

func writeIdentityFile(path string, block *pem.Block) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec
	if err != nil {
		return err
	}
	writeErr := pem.Encode(file, block)
	if err = errors.Join(writeErr, file.Close()); err != nil {
		return errors.Join(err, os.Remove(path))
	}

	return nil
}

func readPassphrase() (string, error) {
	fmt.Fprint(os.Stderr, "Session-file passphrase (hidden): ")
	password, err := term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	defer clear(password)
	if len(password) == 0 {
		return "", errPassphrase
	}

	return string(password), nil
}
