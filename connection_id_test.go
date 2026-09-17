// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/internal/negotiation"
	"github.com/pion/dtls/v3/internal/net/udp"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
)

func TestRandomConnectionIDGenerator(t *testing.T) {
	cases := map[string]struct {
		reason string
		size   int
	}{
		"LengthMatch": {
			reason: "Zero size should match length of generated CID.",
			size:   0,
		},
		"LengthMatchSome": {
			reason: "Non-zero size should match length of generated CID with non-zero.",
			size:   8,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.size, len(RandomCIDGenerator(tc.size)()), "%s\nRandomCIDGenerator mismatch", tc.reason)
		})
	}
}

func TestOnlySendCIDGenerator(t *testing.T) {
	cases := map[string]struct {
		reason string
	}{
		"LengthMatch": {
			reason: "CID length should always be zero.",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equalf(t, 0, len(OnlySendCIDGenerator()()), "%s\nOnlySendCIDGenerator mismatch", tc.reason)
		})
	}
}

func TestCIDDatagramRouter(t *testing.T) {
	cid := []byte("abcd1234")
	cidLen := 8
	epochZeroRecord, err := marshalTestRecord(recordlayer.Header{Epoch: 0, Version: protocol.Version1_2}, &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify})
	assert.NoError(t, err)
	protectedWithoutCIDRecord, err := marshalTestRecord(recordlayer.Header{Epoch: 1, Version: protocol.Version1_2}, &protocol.ApplicationData{Data: []byte("application data")})
	assert.NoError(t, err)

	appData, err := (&protocol.ApplicationData{
		Data: []byte("some data"),
	}).Marshal()
	assert.NoError(t, err)

	inner, err := (&recordlayer.InnerPlaintext{
		Content:  appData,
		RealType: protocol.ContentTypeApplicationData,
	}).Marshal()
	assert.NoError(t, err)

	cidHeader, err := (&recordlayer.Header{
		Epoch:          1,
		Version:        protocol.Version1_2,
		ContentType:    protocol.ContentTypeConnectionID,
		ContentLen:     uint16(len(inner)), //nolint:gosec // G115
		ConnectionID:   cid,
		SequenceNumber: 1,
	}).Marshal()
	assert.NoError(t, err)

	cases := map[string]struct {
		reason   string
		size     int
		datagram []byte
		ok       bool
		want     string
	}{
		"EmptyDatagram":            {reason: "If datagram is empty, we cannot extract an identifier", size: cidLen, datagram: []byte{}, ok: false, want: ""},
		"NotADTLSRecord":           {reason: "If datagram is not a DTLS record, we cannot extract an identifier", size: cidLen, datagram: []byte("not a DTLS record"), ok: false, want: ""},
		"NotAConnectionIDDatagram": {reason: "If datagram does not contain any Connection ID records, we cannot extract an identifier", size: cidLen, datagram: epochZeroRecord, ok: false, want: ""},
		"ProtectedRecordWithoutCIDPrefix": {
			reason: "A protected DTLS 1.2 record without type 25 is invalid after CID negotiation and must not route through a later CID.",
			size:   cidLen,
			datagram: append(
				append(append([]byte{}, protectedWithoutCIDRecord...), cidHeader...),
				inner...,
			),
			ok:   false,
			want: "",
		},
		"OneRecordConnectionID": {reason: "If datagram contains one Connection ID record, we should be able to extract it.", size: cidLen, datagram: append(cidHeader, inner...), ok: true, want: string(cid)},
		"OneRecordConnectionIDAltLength": {
			reason: "If datagram contains one Connection ID record, but it has the wrong length we should not be able to extract it.",
			size:   cidLen,
			datagram: func() []byte {
				altCIDHeader, err := (&recordlayer.Header{
					Epoch:          1,
					Version:        protocol.Version1_2,
					ContentType:    protocol.ContentTypeConnectionID,
					ContentLen:     uint16(len(inner)), //nolint:gosec // G115
					ConnectionID:   []byte("abcd"),
					SequenceNumber: 1,
				}).Marshal()
				assert.NoError(t, err)

				return append(altCIDHeader, inner...)
			}(),
			ok:   false,
			want: "",
		},
		"MultipleRecordOneConnectionID": {
			reason:   "An epoch-zero DTLS 1.2 record may precede a protected Connection ID record in the same datagram.",
			size:     8,
			datagram: append(append(epochZeroRecord, cidHeader...), inner...),
			ok:       true,
			want:     string(cid),
		},
		"MultipleRecordMultipleConnectionID": {
			reason: "If datagram contains multiple records and multiple are Connection ID records, we should extract the first one.",
			size:   8,
			datagram: append(append(append(epochZeroRecord, func() []byte {
				altCIDHeader, err := (&recordlayer.Header{
					Epoch:          1,
					Version:        protocol.Version1_2,
					ContentType:    protocol.ContentTypeConnectionID,
					ContentLen:     uint16(len(inner)), //nolint:gosec // G115
					ConnectionID:   []byte("1234abcd"),
					SequenceNumber: 1,
				}).Marshal()
				assert.NoError(t, err)

				return append(altCIDHeader, inner...)
			}()...), cidHeader...), inner...),
			ok:   true,
			want: "1234abcd",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cid, ok := cidDatagramRouter(tc.size)(tc.datagram)
			assert.Equal(t, tc.ok, ok, "%s\ncidDatagramRouter mismatch", tc.reason)
			assert.Equal(t, tc.want, cid, "%s\ncidDatagramRouter mismatch", tc.reason)
		})
	}
}

func TestCIDDatagramRouter13(t *testing.T) {
	cid := []byte("abcd1234")
	plaintextPrefix, err := marshalTestRecord(recordlayer.Header{Version: protocol.Version1_2}, &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify})
	assert.NoError(t, err)

	makeRecord := func(t *testing.T, connectionID []byte, sequenceNumber uint16) []byte {
		t.Helper()

		record, err := (&recordlayer.CiphertextRecord{Header: recordlayer.UnifiedHeader{ConnectionID: connectionID, SequenceNumber: sequenceNumber}, EncryptedRecord: make([]byte, 16)}).Marshal()
		assert.NoError(t, err)

		return record
	}

	recordWithCID := makeRecord(t, cid, 1)
	recordWithoutCID := makeRecord(t, nil, 2)
	otherCID := []byte("1234abcd")
	recordWithOtherCID := makeRecord(t, otherCID, 3)

	cases := map[string]struct {
		reason   string
		size     int
		datagram []byte
		ok       bool
		want     string
	}{
		"OneRecordConnectionID": {reason: "A unified-header record with the C bit should expose its CID.", size: len(cid), datagram: recordWithCID, ok: true, want: string(cid)},
		"NoConnectionIDBit":     {reason: "A unified-header record without the C bit has no routing identifier.", size: len(cid), datagram: recordWithoutCID, ok: false},
		"WrongConfiguredLength": {reason: "A unified-header CID must have the listener's configured fixed length.", size: len(cid) - 1, datagram: recordWithCID, ok: false},
		"MultipleRecords":       {reason: "The first CID in a datagram containing unified-header records should be used.", size: len(cid), datagram: append(append([]byte{}, recordWithCID...), recordWithOtherCID...), ok: true, want: string(cid)},
		"FixedPrefix":           {reason: "A CID in a unified-header record should route after a fixed-header CID-less prefix.", size: len(cid), datagram: append(append([]byte{}, plaintextPrefix...), recordWithCID...), ok: true, want: string(cid)},
		"MalformedSuffix":       {reason: "A malformed suffix should not hide a CID in an already framed record.", size: len(cid), datagram: append(append([]byte{}, recordWithCID...), 0xff), ok: true, want: string(cid)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := cidDatagramRouter(tc.size)(tc.datagram)
			assert.Equal(t, tc.ok, ok, "%s\ncidDatagramRouter mismatch", tc.reason)
			assert.Equal(t, tc.want, got, "%s\ncidDatagramRouter mismatch", tc.reason)
		})
	}
}

type cidListenerPair struct {
	client, server         *Conn
	clientDone, serverDone chan error
	cancel                 context.CancelFunc
}

func startCIDListenerPair(t *testing.T, listener net.Listener, opts ...ClientOption) cidListenerPair {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	assert.NoError(t, err)
	t.Cleanup(func() { _ = socket.Close() })
	client, err := Client(socket, listener.Addr(), opts...)
	assert.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	pair := cidListenerPair{client: client, clientDone: make(chan error, 1), serverDone: make(chan error, 1), cancel: cancel}
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		accepted <- acceptResult{conn, acceptErr}
	}()
	go func() { pair.clientDone <- client.HandshakeContext(ctx) }()
	select {
	case result := <-accepted:
		assert.NoError(t, result.err)
		t.Cleanup(func() { _ = result.conn.Close() })
		var ok bool
		pair.server, ok = result.conn.(*Conn)
		assert.True(t, ok)
	case <-ctx.Done():
		assert.NoError(t, ctx.Err())
	}
	go func() { pair.serverDone <- pair.server.HandshakeContext(ctx) }()

	return pair
}

type fragmentedServerHelloConn struct {
	net.PacketConn
	fragmented atomic.Bool
}

func (c *fragmentedServerHelloConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	var recordHeader recordlayer.Header
	var handshakeHeader handshake.Header
	if recordHeader.Unmarshal(packet) == nil && recordHeader.ContentType == protocol.ContentTypeHandshake &&
		handshakeHeader.Unmarshal(packet[recordHeader.MarshalSize():]) == nil &&
		handshakeHeader.Type == handshake.TypeServerHello && handshakeHeader.FragmentLength < handshakeHeader.Length {
		c.fragmented.Store(true)
	}

	return c.PacketConn.WriteTo(packet, addr)
}

func TestListenConnectionIDFragmentedServerHello(t *testing.T) {
	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	for versionName, version := range map[string]protocol.Version{"DTLS12": protocol.Version1_2, "DTLS13": protocol.Version1_3} {
		t.Run(versionName, func(t *testing.T) {
			socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			assert.NoError(t, err)
			transport := &fragmentedServerHelloConn{PacketConn: socket}
			listener, err := Listen(transport,
				WithCertificates(certificate), WithMinVersion(version), WithMaxVersion(version), WithMTU(48),
				WithInsecureSkipVerifyHello(true),
				WithConnectionID(func() []byte { return []byte("server-cid") }, CIDPathMigrationUnsafe),
			)
			assert.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			pair := startCIDListenerPair(t, listener,
				WithInsecureSkipVerify(true), WithMinVersion(version), WithMaxVersion(version), WithMTU(48),
				WithConnectionID(func() []byte { return []byte("client-cid") }, CIDPathMigrationUnsafe),
			)
			assert.NoError(t, <-pair.clientDone)
			assert.NoError(t, <-pair.serverDone)
			assert.True(t, transport.fragmented.Load(), "ServerHello must actually be fragmented")
			assertCIDListenerRebinding(t, listener, pair.client, pair.server)
		})
	}
}

func TestListenConnectionIDCollisionPreservesAssociation(t *testing.T) {
	certificate, err := selfsign.GenerateSelfSigned()
	assert.NoError(t, err)
	for versionName, version := range map[string]protocol.Version{"DTLS12": protocol.Version1_2, "DTLS13": protocol.Version1_3} {
		t.Run(versionName, func(t *testing.T) {
			listener, err := ListenAddr("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
				WithCertificates(certificate), WithMinVersion(version), WithMaxVersion(version),
				WithConnectionID(func() []byte { return []byte("shared-cid") }, CIDPathMigrationUnsafe),
			)
			assert.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			opts := []ClientOption{
				WithInsecureSkipVerify(true), WithMinVersion(version), WithMaxVersion(version),
				WithConnectionID(OnlySendCIDGenerator(), CIDPathMigrationUnsafe),
			}
			first := startCIDListenerPair(t, listener, opts...)
			assert.NoError(t, <-first.clientDone)
			assert.NoError(t, <-first.serverDone)
			second := startCIDListenerPair(t, listener, opts...)
			assert.ErrorIs(t, <-second.serverDone, udp.ErrCIDInUse)
			second.cancel()
			assert.Error(t, <-second.clientDone)
			_ = second.server.Close()
			_ = second.client.Close()
			assertCIDListenerData(t, first.client, first.server)
			assertCIDListenerData(t, first.server, first.client)
			assertCIDListenerRebinding(t, listener, first.client, first.server)
		})
	}
}

func TestConnectionIDPreflight(t *testing.T) {
	cid := []byte("own-cid!")
	state12 := dtlsstate.NewState12(false)
	state12.SetLocalConnectionID(cid)
	state13 := dtlsstate.NewState13(false)
	state13.CommitNegotiatedExtensions(&negotiation.ConnectionID{ServerCID: cid})
	for versionName, state := range map[string]dtlsstate.Active{"DTLS12": &state12, "DTLS13": &state13} {
		t.Run(versionName, func(t *testing.T) {
			conn := &Conn{state: state}
			version := dtlsstate.CommonState(state).LocalVersion
			own := marshalCIDPreflightRecord(t, version, cid)
			unknown := marshalCIDPreflightRecord(t, version, []byte("missing!"))
			prefix := marshalCIDPreflightRecord(t, version, nil)
			for _, testCase := range []struct {
				name    string
				records [][]byte
				want    int
			}{
				{name: "MatchingCID", records: [][]byte{prefix, own}, want: 2},
				{name: "UnknownSuffix", records: [][]byte{prefix, own, unknown, own}, want: 2},
				{name: "UnknownFirstCID", records: [][]byte{prefix, unknown, own}},
			} {
				t.Run(testCase.name, func(t *testing.T) {
					records, unpackErr := conn.unpackDatagram(bytes.Join(testCase.records, nil))
					if testCase.want == 0 {
						assert.ErrorIs(t, unpackErr, dtlserrors.ErrInvalidCiphertextHeader)
						assert.Empty(t, records)

						return
					}
					assert.NoError(t, unpackErr)
					assert.Equal(t, testCase.records[:testCase.want], records)
				})
			}
		})
	}
}

func marshalCIDPreflightRecord(t *testing.T, version protocol.Version, cid []byte) []byte {
	t.Helper()
	if version == protocol.Version1_3 {
		raw, err := (&recordlayer.CiphertextRecord{
			Header: recordlayer.UnifiedHeader{ConnectionID: cid, SequenceNumber: 1}, EncryptedRecord: make([]byte, 16),
		}).Marshal()
		assert.NoError(t, err)

		return raw
	}
	if len(cid) == 0 {
		raw, err := marshalTestRecord(recordlayer.Header{Version: version}, &protocol.ChangeCipherSpec{})
		assert.NoError(t, err)

		return raw
	}
	header, err := (&recordlayer.Header{
		Epoch: 1, Version: version, ContentType: protocol.ContentTypeConnectionID,
		ContentLen: 16, ConnectionID: cid, SequenceNumber: 1,
	}).Marshal()
	assert.NoError(t, err)

	return append(header, make([]byte, 16)...)
}

func assertCIDListenerData(t *testing.T, sender, receiver *Conn) {
	t.Helper()
	payload := []byte("association data")
	_, err := sender.Write(payload)
	assert.NoError(t, err)
	assert.NoError(t, receiver.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, 64)
	n, err := receiver.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, payload, buffer[:n])
}

func assertCIDListenerRebinding(t *testing.T, listener net.Listener, client, server *Conn) {
	t.Helper()
	rebound, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	assert.NoError(t, err)
	t.Cleanup(func() { _ = rebound.Close() })
	client.writeLock.Lock()
	defer client.writeLock.Unlock()
	payload := []byte("rebound association")
	packet := client.newApplicationDataPacket(payload)
	packet.Epoch = dtlsstate.CommonState(client.state).LocalEpoch()
	datagrams, _, err := client.prepareRawPacketsTracked([]*dtlsflight.Outbound{packet})
	assert.NoError(t, err)
	assert.Len(t, datagrams, 1)
	_, err = rebound.WriteTo(datagrams[0].raw, listener.Addr())
	assert.NoError(t, err)
	assert.NoError(t, server.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, 64)
	n, err := server.Read(buffer)
	assert.NoError(t, err)
	assert.Equal(t, payload, buffer[:n])
	assert.Equal(t, rebound.LocalAddr().String(), server.RemoteAddr().String())
}
