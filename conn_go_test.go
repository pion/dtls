// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package dtls

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/pion/transport/v4/dpipe"
	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errAcceptedConnectionNotDTLS = errors.New("accepted connection is not a DTLS Conn")

func TestListenConnectionIDRebindingRequiresRRC(t *testing.T) {
	tests := map[string]struct {
		clientMin, clientMax, serverMin, serverMax, negotiated protocol.Version
	}{
		"DTLS12": {
			clientMin: protocol.Version1_2, clientMax: protocol.Version1_2,
			serverMin: protocol.Version1_2, serverMax: protocol.Version1_2,
			negotiated: protocol.Version1_2,
		},
		"DualStackToDTLS12": {
			clientMin: protocol.Version1_2, clientMax: protocol.Version1_3,
			serverMin: protocol.Version1_2, serverMax: protocol.Version1_2,
			negotiated: protocol.Version1_2,
		},
		"DTLS13": {
			clientMin: protocol.Version1_3, clientMax: protocol.Version1_3,
			serverMin: protocol.Version1_3, serverMax: protocol.Version1_3,
			negotiated: protocol.Version1_3,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			testListenConnectionIDRebindingRequiresRRC(
				t, test.clientMin, test.clientMax, test.serverMin, test.serverMax, test.negotiated,
			)
		})
	}
}

func testListenConnectionIDRebindingRequiresRRC(
	t *testing.T,
	clientMin, clientMax, serverMin, serverMax, negotiatedVersion protocol.Version,
) {
	t.Helper()
	defer test.CheckRoutines(t)()
	defer test.TimeOut(10 * time.Second).Stop()

	serverCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	serverCID := []byte("server-cid")
	listener, err := ListenWithOptions(
		"udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		WithCertificates(serverCert),
		WithMinVersion(serverMin),
		WithMaxVersion(serverMax),
		WithConnectionID(func() []byte { return serverCID }, CIDPathMigrationRRC),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, listener.Close())
	}()

	initialSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	client, err := ClientWithOptions(
		initialSocket,
		listener.Addr(),
		WithInsecureSkipVerify(true),
		WithMinVersion(clientMin),
		WithMaxVersion(clientMax),
		WithConnectionID(func() []byte { return []byte("client-cid") }, CIDPathMigrationRRC),
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, client.Close())
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type serverResult struct {
		conn *Conn
		err  error
	}
	serverCh := make(chan serverResult, 1)
	go func() {
		accepted, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverCh <- serverResult{err: acceptErr}

			return
		}
		server, ok := accepted.(*Conn)
		if !ok {
			serverCh <- serverResult{err: errAcceptedConnectionNotDTLS}

			return
		}
		serverCh <- serverResult{conn: server, err: server.HandshakeContext(ctx)}
	}()

	require.NoError(t, client.HandshakeContext(ctx))
	result := <-serverCh
	require.NoError(t, result.err)
	server := result.conn
	defer func() {
		require.NoError(t, server.Close())
	}()
	require.Equal(t, negotiatedVersion, dtlsstate.CommonState(client.state).LocalVersion)
	require.Equal(t, negotiatedVersion, dtlsstate.CommonState(server.state).LocalVersion)
	require.True(t, dtlsstate.CommonState(client.state).RRCNegotiated)
	require.True(t, dtlsstate.CommonState(server.state).RRCNegotiated)
	initialRemoteAddr := server.RemoteAddr().String()

	reboundSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() {
		require.NoError(t, reboundSocket.Close())
	}()

	reboundPacket := client.newApplicationDataPacket([]byte("rebound"))
	reboundPacket.Record.Header.Epoch = dtlsstate.CommonState(client.state).LocalEpoch()
	datagrams, _, err := client.prepareRawPacketsTracked([]*dtlsflight.Packet{reboundPacket})
	require.NoError(t, err)
	require.Len(t, datagrams, 1)
	_, err = reboundSocket.WriteTo(datagrams[0].raw, listener.Addr())
	require.NoError(t, err)

	require.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 64)
	n, err := server.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("rebound"), buf[:n])
	assert.Equal(t, initialRemoteAddr, server.RemoteAddr().String())

	require.NoError(t, reboundSocket.SetReadDeadline(time.Now().Add(time.Second)))
	n, source, err := reboundSocket.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, listener.Addr().String(), source.String())

	challengeRecords, err := client.unpackDatagram(buf[:n])
	require.NoError(t, err)
	require.Len(t, challengeRecords, 1)
	var challenge protocol.ReturnRoutabilityCheck
	if negotiatedVersion.Equal(protocol.Version1_3) {
		challengeRecord, unmarshalErr := client.unmarshalCiphertextRecord(challengeRecords[0])
		require.NoError(t, unmarshalErr)
		challengePlaintext, _, _, openErr := client.openCiphertextRecord(challengeRecord)
		require.NoError(t, openErr)
		require.Equal(t, protocol.ContentTypeReturnRoutabilityCheck, challengePlaintext.RealType)
		require.NoError(t, challenge.Unmarshal(challengePlaintext.Content))
	} else {
		prepared, ok := client.prepareIncomingPacket(challengeRecords[0], source, nil)
		require.True(t, ok)
		var record recordlayer.RecordLayer
		require.NoError(t, record.Unmarshal(prepared.buf))
		rrc, ok := record.Content.(*protocol.ReturnRoutabilityCheck)
		require.True(t, ok)
		challenge = *rrc
	}
	assert.Equal(t, protocol.ReturnRoutabilityCheckPathChallenge, challenge.MessageType)

	responsePacket := &dtlsflight.Packet{
		Record: &recordlayer.RecordLayer{
			Header: recordlayer.Header{
				Version: protocol.Version1_2,
				Epoch:   dtlsstate.CommonState(client.state).LocalEpoch(),
			},
			Content: &protocol.ReturnRoutabilityCheck{
				MessageType: protocol.ReturnRoutabilityCheckPathResponse,
				Cookie:      challenge.Cookie,
			},
		},
		ShouldWrapCID: negotiatedVersion.Equal(protocol.Version1_2) && client.state.ShouldWrapConnectionID(),
		ShouldEncrypt: true,
	}
	responseDatagrams, _, err := client.prepareRawPacketsTracked([]*dtlsflight.Packet{responsePacket})
	require.NoError(t, err)
	require.Len(t, responseDatagrams, 1)
	_, err = reboundSocket.WriteTo(responseDatagrams[0].raw, listener.Addr())
	require.NoError(t, err)

	secondReboundPacket := client.newApplicationDataPacket([]byte("validated"))
	secondReboundPacket.Record.Header.Epoch = dtlsstate.CommonState(client.state).LocalEpoch()
	secondDatagrams, _, err := client.prepareRawPacketsTracked([]*dtlsflight.Packet{secondReboundPacket})
	require.NoError(t, err)
	require.Len(t, secondDatagrams, 1)
	_, err = reboundSocket.WriteTo(secondDatagrams[0].raw, listener.Addr())
	require.NoError(t, err)

	require.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))
	n, err = server.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("validated"), buf[:n])
	assert.Equal(t, reboundSocket.LocalAddr().String(), server.RemoteAddr().String())

	_, err = server.Write([]byte("new path"))
	require.NoError(t, err)
	require.NoError(t, reboundSocket.SetReadDeadline(time.Now().Add(time.Second)))
	n, source, err = reboundSocket.ReadFrom(buf)
	require.NoError(t, err)
	assert.Positive(t, n)
	assert.Equal(t, listener.Addr().String(), source.String())
}

func TestContextConfig(t *testing.T) { //nolint:cyclop
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	addrListen, err := net.ResolveUDPAddr("udp", "localhost:0")
	assert.NoError(t, err)

	// Dummy listener
	listen, err := net.ListenUDP("udp", addrListen)
	assert.NoError(t, err)
	defer func() {
		_ = listen.Close()
	}()
	addr, ok := listen.LocalAddr().(*net.UDPAddr)
	assert.True(t, ok)

	cert, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)

	clientOpts := []ClientOption{
		WithCertificates(cert),
	}
	serverOpts := []ServerOption{
		WithCertificates(cert),
	}

	dials := map[string]struct {
		f func() (func() (net.Conn, error), func())
	}{
		"Dial": {
			f: func() (func() (net.Conn, error), func()) {
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)

				return func() (net.Conn, error) {
						conn, err := DialWithOptions("udp", addr, clientOpts...)
						if err != nil {
							return nil, err
						}

						return conn, conn.HandshakeContext(ctx)
					}, func() {
						cancel()
					}
			},
		},
		"Client": {
			f: func() (func() (net.Conn, error), func()) {
				ca, _ := dpipe.Pipe()
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)

				return func() (net.Conn, error) {
						conn, err := ClientWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), clientOpts...)
						if err != nil {
							return nil, err
						}

						return conn, conn.HandshakeContext(ctx)
					}, func() {
						_ = ca.Close()
						cancel()
					}
			},
		},
		"Server": {
			f: func() (func() (net.Conn, error), func()) {
				ca, _ := dpipe.Pipe()
				ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)

				return func() (net.Conn, error) {
						conn, err := ServerWithOptions(dtlsnet.PacketConnFromConn(ca), ca.RemoteAddr(), serverOpts...)
						if err != nil {
							return nil, err
						}

						return conn, conn.HandshakeContext(ctx)
					}, func() {
						_ = ca.Close()
						cancel()
					}
			},
		},
	}

	type dialResult struct {
		err         error
		ok          bool
		completedAt time.Time
	}

	for name, dial := range dials {
		t.Run(name, func(t *testing.T) {
			done := make(chan dialResult, 1)
			startedAt := time.Now()

			go func() {
				d, cancel := dial.f()
				conn, err := d()
				defer cancel()
				var netError net.Error
				if err == nil {
					_ = conn.Close()
				}

				done <- dialResult{
					err:         err,
					ok:          errors.As(err, &netError) && netError.Temporary(), //nolint:staticcheck
					completedAt: time.Now(),
				}
			}()

			const earlyCancelWindow = 20 * time.Millisecond
			time.Sleep(earlyCancelWindow)

			assertResult := func(result dialResult) {
				assert.GreaterOrEqual(
					t,
					result.completedAt.Sub(startedAt),
					earlyCancelWindow,
					"Invalid cancel timing",
				)
				if !result.ok {
					assert.Fail(t, "Dial failed with unexpected error", "err: %v", result.err)
				}
			}

			select {
			case result := <-done:
				assertResult(result)

				return
			default:
			}

			select {
			case result := <-done:
				assertResult(result)
			case <-time.After(time.Second):
				assert.Fail(t, "Dial did not finish after context cancellation")
			}
		})
	}
}
