// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import "github.com/pion/dtls/v4/pkg/protocol"

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
				if acknowledgeFragments(f.pending, fragment) {
					changed[fragment.MessageSequence] = struct{}{}
				}
			}
		}
	}
	for sequence := range changed {
		pending := f.pendingForMessage(sequence)
		result.Messages = append(result.Messages, MessageACKProgress{MessageSequence: sequence, Changed: true, Complete: len(pending) == 0})
	}

	return result
}

func acknowledgeFragments(pending map[SentHandshakeFragment]struct{}, ack SentHandshakeFragment) bool {
	if _, ok := pending[ack]; ok {
		delete(pending, ack)

		return true
	}
	changed := false
	for fragment := range pending {
		if fragment.MessageSequence != ack.MessageSequence {
			continue
		}
		start, end := max(fragment.Offset, ack.Offset), min(fragment.Offset+fragment.Length, ack.Offset+ack.Length)
		if start >= end && fragment != ack {
			continue
		}
		delete(pending, fragment)
		if start > fragment.Offset {
			pending[SentHandshakeFragment{MessageSequence: fragment.MessageSequence, Offset: fragment.Offset, Length: start - fragment.Offset}] = struct{}{}
		}
		if end < fragment.Offset+fragment.Length {
			pending[SentHandshakeFragment{MessageSequence: fragment.MessageSequence, Offset: end, Length: fragment.Offset + fragment.Length - end}] = struct{}{}
		}
		changed = true
	}

	return changed
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
