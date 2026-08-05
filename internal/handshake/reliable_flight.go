// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import "github.com/pion/dtls/v3/pkg/protocol"

// reliableFlight tracks one retransmission state machine's logical fragments
// independently of the record numbers assigned to each transmission.
type reliableFlight struct {
	records map[protocol.RecordNumber][]SentHandshakeFragment
	pending map[SentHandshakeFragment]struct{}
}

func (f *reliableFlight) reset() {
	f.records = map[protocol.RecordNumber][]SentHandshakeFragment{}
	f.pending = map[SentHandshakeFragment]struct{}{}
}

func (f *reliableFlight) track(result *WriteResult) {
	if result == nil {
		return
	}
	for _, record := range result.TrackedRecords {
		f.records[record.Number] = record.Fragments
		for _, fragment := range record.Fragments {
			f.pending[fragment] = struct{}{}
		}
	}
}

func (f *reliableFlight) acknowledge(acks []protocol.ACK) ACKResult {
	result := ACKResult{}
	changed := map[uint16]struct{}{}
	for _, ack := range acks {
		result.Empty = result.Empty || len(ack.Records) == 0
		for _, number := range ack.Records {
			for _, fragment := range f.records[number] {
				if _, ok := f.pending[fragment]; ok {
					delete(f.pending, fragment)
					changed[fragment.MessageSequence] = struct{}{}
				}
			}
		}
	}
	for sequence := range changed {
		pending := f.pendingForMessage(sequence)
		result.Messages = append(result.Messages, MessageACKProgress{
			MessageSequence: sequence, Changed: true, Complete: len(pending) == 0,
		})
	}

	return result
}

func (f *reliableFlight) pendingForMessage(sequence uint16) map[uint32]uint32 {
	pending := map[uint32]uint32{}
	for fragment := range f.pending {
		if fragment.MessageSequence == sequence {
			pending[fragment.Offset] = fragment.Length
		}
	}

	return pending
}
