// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v4/internal/closer"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight13 "github.com/pion/dtls/v4/internal/flight/flight13"
	"github.com/pion/dtls/v4/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/pion/dtls/v4/pkg/protocol/recordlayer"
	"github.com/pion/transport/v5/netctx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathTransport(t *testing.T) {
	listen := func() net.PacketConn {
		socket, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = socket.Close() })

		return socket
	}
	peer, initial, candidate := listen(), listen(), listen()
	conn := &Conn{closed: closer.NewCloser(), rAddr: peer.LocalAddr(), readBufferPool: readBufferPoolForSize(1500)}
	transport := newPathTransport(conn, netctx.NewPacketConn(initial))
	t.Cleanup(func() { _ = transport.Close() })
	path := transport.add(netctx.NewPacketConn(candidate))
	go path.read()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buffer := make([]byte, 1500)
	for _, socket := range []net.PacketConn{initial, candidate} {
		_, err := peer.WriteTo([]byte("request"), socket.LocalAddr())
		require.NoError(t, err)
		n, addr, err := transport.ReadFromContext(ctx, buffer)
		require.NoError(t, err)
		assert.Equal(t, "request", string(buffer[:n]))
		assert.True(t, sameNetworkAddress(peer.LocalAddr(), addr))
		_, err = transport.WriteToContext(ctx, []byte("reply"), addr)
		require.NoError(t, err)
		require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
		n, source, err := peer.ReadFrom(buffer)
		require.NoError(t, err)
		assert.Equal(t, "reply", string(buffer[:n]))
		assert.Equal(t, socket.LocalAddr(), source)
		require.NoError(t, conn.updateRemoteAddr(addr))
		assert.Equal(t, peer.LocalAddr(), conn.rAddr)
	}
	_, err := transport.WriteToContext(ctx, []byte("active"), peer.LocalAddr())
	require.NoError(t, err)
	_, source, err := peer.ReadFrom(buffer)
	require.NoError(t, err)
	assert.Equal(t, initial.LocalAddr(), source)
	for _, socket := range []net.PacketConn{initial, candidate} {
		require.NoError(t, socket.SetReadDeadline(time.Now().Add(time.Second)))
	}
	require.NoError(t, transport.Close())
	require.NoError(t, transport.Close())
	for _, socket := range []net.PacketConn{initial, candidate} {
		_, _, err = socket.ReadFrom(buffer)
		assert.ErrorIs(t, err, net.ErrClosed)
	}
	assert.ErrorIs(t, context.Cause(path.lifetime), ErrConnClosed)
}

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
	epochZeroRecord, err := marshalTestRecord(recordlayer.RecordConfig{Epoch: 0, Version: protocol.Version1_2}, &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify})
	assert.NoError(t, err)
	protectedWithoutCIDRecord, err := marshalTestRecord(recordlayer.RecordConfig{Epoch: 1, Version: protocol.Version1_2}, &protocol.ApplicationData{Data: []byte("application data")})
	assert.NoError(t, err)

	appData, err := (&protocol.ApplicationData{
		Data: []byte("some data"),
	}).Marshal()
	assert.NoError(t, err)

	inner, err := recordlayer.MarshalInnerPlaintext(appData, protocol.ContentTypeApplicationData, 0)
	assert.NoError(t, err)

	cidRecord, err := recordlayer.MarshalRecord(recordlayer.RecordConfig{
		ContentType: protocol.ContentTypeConnectionID, Version: protocol.Version1_2,
		Epoch: 1, SequenceNumber: 1, ConnectionID: cid,
	}, inner)
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
			reason:   "A protected DTLS 1.2 record without type 25 is invalid after CID negotiation and must not route through a later CID.",
			size:     cidLen,
			datagram: append(bytes.Clone(protectedWithoutCIDRecord), cidRecord...),
			ok:       false,
			want:     "",
		},
		"OneRecordConnectionID": {reason: "If datagram contains one Connection ID record, we should be able to extract it.", size: cidLen, datagram: cidRecord, ok: true, want: string(cid)},
		"OneRecordConnectionIDAltLength": {
			reason: "If datagram contains one Connection ID record, but it has the wrong length we should not be able to extract it.",
			size:   cidLen,
			datagram: func() []byte {
				altCIDRecord, err := recordlayer.MarshalRecord(recordlayer.RecordConfig{
					ContentType: protocol.ContentTypeConnectionID, Version: protocol.Version1_2,
					Epoch: 1, SequenceNumber: 1, ConnectionID: []byte("abcd"),
				}, inner)
				assert.NoError(t, err)

				return altCIDRecord
			}(),
			ok:   false,
			want: "",
		},
		"MultipleRecordOneConnectionID": {
			reason:   "An epoch-zero DTLS 1.2 record may precede a protected Connection ID record in the same datagram.",
			size:     8,
			datagram: append(bytes.Clone(epochZeroRecord), cidRecord...),
			ok:       true,
			want:     string(cid),
		},
		"MultipleRecordMultipleConnectionID": {
			reason: "If datagram contains multiple records and multiple are Connection ID records, we should extract the first one.",
			size:   8,
			datagram: append(append(bytes.Clone(epochZeroRecord), func() []byte {
				altCIDRecord, err := recordlayer.MarshalRecord(recordlayer.RecordConfig{
					ContentType: protocol.ContentTypeConnectionID, Version: protocol.Version1_2,
					Epoch: 1, SequenceNumber: 1, ConnectionID: []byte("1234abcd"),
				}, inner)
				assert.NoError(t, err)

				return altCIDRecord
			}()...), cidRecord...),
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
	plaintextPrefix, err := marshalTestRecord(recordlayer.RecordConfig{Version: protocol.Version1_2}, &alert.Alert{Level: alert.Warning, Description: alert.CloseNotify})
	assert.NoError(t, err)

	makeRecord := func(t *testing.T, connectionID []byte, sequenceNumber uint16) []byte {
		t.Helper()

		record, err := recordlayer.MarshalCiphertext(recordlayer.CiphertextConfig{ConnectionID: connectionID, SequenceNumber: sequenceNumber, TwoByteSequence: true, LengthPresent: true}, make([]byte, 16))
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
		raw, err := recordlayer.MarshalCiphertext(recordlayer.CiphertextConfig{ConnectionID: cid, SequenceNumber: 1, TwoByteSequence: true, LengthPresent: true}, make([]byte, 16))
		assert.NoError(t, err)

		return raw
	}
	if len(cid) == 0 {
		raw, err := marshalTestRecord(recordlayer.RecordConfig{Version: version}, &protocol.ChangeCipherSpec{})
		assert.NoError(t, err)

		return raw
	}
	raw, err := recordlayer.MarshalRecord(recordlayer.RecordConfig{
		ContentType: protocol.ContentTypeConnectionID, Version: version,
		Epoch: 1, SequenceNumber: 1, ConnectionID: cid,
	}, make([]byte, 16))
	assert.NoError(t, err)

	return raw
}

func pendingCIDTestOffer(t *testing.T, conn *Conn) (*dtlsstate.State13, *dtlsstate.TrafficKeyState) {
	t.Helper()
	state, err := dtlsstate.As13(conn.state)
	assert.NoError(t, err)
	trafficKeys := state.TrafficKeys
	state.TrafficKeys = nil
	state.SetRemoteEpoch(dtlsflight13.EpochInitial)
	_, snapshot, err := negotiation.FinalizeClientHello(&handshake.MessageClientHello{
		Version: protocol.Version1_2, CipherSuiteIDs: []uint16{uint16(cryptosuite.TLS_AES_128_GCM_SHA256)},
		Extensions: []extension.Value{
			&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
			&extension.SignatureAlgorithms{Schemes: []uint16{0x0403}},
			&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}},
			&extension13.ClientKeyShare{},
			&extension.ConnectionID{CID: []byte{0xc1}},
		},
	}, nil)
	assert.NoError(t, err)
	assert.NoError(t, state.RecordLocalClientHello(snapshot))

	return state, trafficKeys
}

func pendingCIDTestRecord(t *testing.T, peer *testRecordProtection13, cid []byte, sequence uint16) []byte {
	t.Helper()
	record, err := peer.SealRecord(recordlayer.CiphertextConfig{EpochLow: 2, ConnectionID: cid}, uint64(sequence), protocol.ContentTypeHandshake, encryptedExtensionsHandshakeWithSequence(t, sequence))
	assert.NoError(t, err)
	raw, err := record.Marshal()
	assert.NoError(t, err)

	return raw
}

func TestPendingCIDDatagramFinalDecision(t *testing.T) {
	for _, test := range []struct {
		name           string
		response       *extension.ConnectionID
		wantWithoutCID int
		wantWithCID    int
	}{
		{name: "omitted", wantWithoutCID: 2, wantWithCID: 1},
		{name: "present empty", response: &extension.ConnectionID{}, wantWithCID: 2},
		{name: "present nonempty", response: &extension.ConnectionID{CID: []byte{0x51}}, wantWithCID: 2},
	} {
		for _, withCID := range []bool{false, true} {
			name := test.name + "/CID-less"
			wantRecords := test.wantWithoutCID
			if withCID {
				name = test.name + "/CID-bearing"
				wantRecords = test.wantWithCID
			}
			t.Run(name, func(t *testing.T) {
				conn, peer := newTestConnWithReadProtection(t)
				state, trafficKeys := pendingCIDTestOffer(t, conn)
				var finalCID []byte
				if withCID {
					finalCID = []byte{0xc1}
				}
				first := pendingCIDTestRecord(t, peer, nil, 0)
				second := pendingCIDTestRecord(t, peer, finalCID, 1)
				datagram := append(bytes.Clone(first), second...)
				assert.False(t, conn.hasInboundRecordProtection())
				summary, err := conn.processDatagram(t.Context(), datagram, nil, &readBufferLease{conn: conn})
				assert.NoError(t, err)
				assert.False(t, summary.containsHandshake)
				assert.Len(t, conn.encryptedPackets, 2)
				for _, packet := range conn.encryptedPackets {
					assert.True(t, packet.pendingCID)
					assert.Equal(t, withCID, packet.datagramContainsCID)
				}
				clear(datagram)
				assert.Equal(t, first, conn.encryptedPackets[0].data)
				assert.Equal(t, second, conn.encryptedPackets[1].data)
				assert.NoError(t, conn.handleQueuedPackets(t.Context()))
				assert.Len(t, conn.encryptedPackets, 2)
				_, opened := state.HighestRemoteSequenceNumber(dtlsflight13.EpochHandshake)
				assert.False(t, opened)
				assert.Empty(t, conn.pendingACKs)

				var response []extension.Value
				if test.response != nil {
					response = append(response, test.response)
				}
				state.CommitNegotiatedExtensions(negotiation.DecideConnectionID(state.LocalClientHelloSnapshots.Current(), response))
				state.TrafficKeys = trafficKeys
				state.SetRemoteEpoch(dtlsflight13.EpochHandshake)
				assert.True(t, conn.hasInboundRecordProtection())
				assert.NoError(t, conn.handleQueuedPackets(t.Context()))
				assert.Empty(t, conn.encryptedPackets)
				for sequence := range uint16(2) {
					_, delivered := conn.handshakeCache.PullExact(sequence, false)
					assert.Equal(t, int(sequence) < wantRecords, delivered)
				}
				highest, opened := state.HighestRemoteSequenceNumber(dtlsflight13.EpochHandshake)
				assert.Equal(t, wantRecords > 0, opened)
				if opened {
					assert.EqualValues(t, wantRecords-1, highest)
				}
				assert.Len(t, conn.pendingACKs, wantRecords)
				for sequence, ack := range conn.pendingACKs {
					assert.EqualValues(t, dtlsflight13.EpochHandshake, ack.Epoch)
					assert.EqualValues(t, sequence, ack.SequenceNumber)
				}
			})
		}
	}
}

func TestDynamicCIDAcceptance(t *testing.T) {
	state := dtlsstate.NewState13(false)
	state.CommitNegotiatedExtensions(&negotiation.ConnectionID{ServerCID: []byte("original")})
	conn := &Conn{state: &state, closed: closer.NewCloser()}
	alias := []byte("newalias")
	added, err := conn.reserveLocalCIDs([][]byte{alias, alias, []byte("original")})
	assert.NoError(t, err)
	assert.Len(t, added, 1)
	alias[0] = 'X'
	for _, cid := range []string{"original", "newalias"} {
		raw := marshalCIDPreflightRecord(t, protocol.Version1_3, []byte(cid))
		records, unpackErr := conn.unpackDatagram(raw)
		assert.NoError(t, unpackErr)
		assert.Len(t, records, 1)
		_, err = conn.unmarshalCiphertextRecord(raw, false)
		assert.NoError(t, err)
	}
	unknown := marshalCIDPreflightRecord(t, protocol.Version1_3, []byte("unknown!"))
	_, err = conn.unpackDatagram(unknown)
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)
	_, err = conn.unmarshalCiphertextRecord(unknown, false)
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidCiphertextHeader)
	prefix := marshalCIDPreflightRecord(t, protocol.Version1_3, nil)
	aliasRecord := marshalCIDPreflightRecord(t, protocol.Version1_3, added[0])
	records, err := conn.unpackDatagram(bytes.Join([][]byte{prefix, aliasRecord}, nil))
	assert.NoError(t, err)
	assert.Len(t, records, 2)
	_, err = conn.unmarshalCiphertextRecord(prefix, true)
	assert.NoError(t, err)

	_, err = conn.reserveLocalCIDs([][]byte{[]byte("rollback"), []byte("short")})
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidConnectionIDLength)
	assert.False(t, conn.acceptsInboundCID([]byte("rollback")))
	conn.removeLocalCIDs(added)
	assert.False(t, conn.acceptsInboundCID([]byte("newalias")))
	assert.True(t, conn.acceptsInboundCID([]byte("original")))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			_, _ = conn.unpackDatagram(aliasRecord)
			_, _ = conn.unmarshalCiphertextRecord(aliasRecord, false)
		}
	}()
	for range 100 {
		added, err = conn.reserveLocalCIDs([][]byte{[]byte("newalias")})
		assert.NoError(t, err)
		conn.removeLocalCIDs(added)
	}
	wg.Wait()
	conn.closed.Close()
	_, err = conn.reserveLocalCIDs([][]byte{[]byte("newalias")})
	assert.ErrorIs(t, err, ErrConnClosed)
}

func TestPeerConnectionIDSelection(t *testing.T) {
	state := dtlsstate.NewState13(false)
	state.CommitNegotiatedExtensions(&negotiation.ConnectionID{ServerCID: []byte("local"), ClientCID: []byte("peer")})
	conn := &Conn{state: &state, closed: closer.NewCloser()}
	adapter := handshakeConn{conn: conn}
	spare := []byte("a-longer-peer-id")
	require.NoError(t, adapter.CommitPeerConnectionIDs(&handshake.MessageNewConnectionID{
		Usage: handshake.ConnectionIDSpare, CIDs: [][]byte{spare, spare, nil},
	}))
	spare[0] = 'X'
	assert.Equal(t, []byte("peer"), state.CID.Send.Active)
	assert.Equal(t, [][]byte{[]byte("a-longer-peer-id"), nil}, state.CID.Send.Spares)
	require.NoError(t, adapter.CommitPeerConnectionIDs(&handshake.MessageNewConnectionID{Usage: handshake.ConnectionIDImmediate, CIDs: [][]byte{nil}}))
	assert.False(t, state.CID.Send.UseCID)
	assert.Empty(t, state.CID.Send.Active)
	assert.Equal(t, [][]byte{[]byte("a-longer-peer-id")}, state.CID.Send.Spares)
	for i := range dtlsstate.MaxConnectionIDs + 5 {
		require.NoError(t, adapter.CommitPeerConnectionIDs(&handshake.MessageNewConnectionID{
			Usage: handshake.ConnectionIDSpare, CIDs: [][]byte{{byte(i)}}, //nolint:gosec
		}))
	}
	assert.Len(t, state.CID.Send.Spares, dtlsstate.MaxConnectionIDs)
	require.NoError(t, adapter.CommitPeerConnectionIDs(&handshake.MessageNewConnectionID{Usage: handshake.ConnectionIDImmediate, CIDs: [][]byte{[]byte("restored")}}))
	assert.True(t, state.CID.Send.UseCID)
	assert.Equal(t, []byte("restored"), state.CID.Send.Active)
}
