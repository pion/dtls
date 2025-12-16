// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"sort"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

const (
	// 2 megabytes.
	fragmentBufferMaxSize  = 2000000
	fragmentBufferMaxCount = 1000
)

type fragment struct {
	offset uint32
	data   []byte
}

type fragments struct {
	// non-overlapping chunks, sorted by offset.
	frags []*fragment

	receivedLength  uint32 // union length of covered bytes (no double-counting)
	handshakeLength uint32

	epoch      uint16
	baseHeader handshake.Header // used to rebuild header on pop()
}

type fragmentBuffer struct {
	// map of MessageSequenceNumbers that hold slices of fragments
	cache map[uint16]*fragments

	currentMessageSequenceNumber uint16

	totalBufferSize    int // total stored payload bytes across all messages (no overlaps)
	totalFragmentCount int // total stored chunks across all messages
}

func newFragmentBuffer() *fragmentBuffer {
	return &fragmentBuffer{cache: map[uint16]*fragments{}}
}

// scanUncovered iterates uncovered sub-ranges of [start,end) given existing non-overlapping,
// sorted fragments. visit is called with [uStart,uEnd) in ascending order.
func (m *fragments) scanUncovered(start, end uint32, visit func(uStart, uEnd uint32)) {
	if start >= end {
		return
	}

	// find first fragment with end > start.
	i := sort.Search(len(m.frags), func(i int) bool {
		ex := m.frags[i]
		exStart := ex.offset
		exEnd := exStart + uint32(len(ex.data)) //nolint:gosec // bounded by caps

		return exEnd > start
	})

	pos := start
	for ; i < len(m.frags); i++ {
		ex := m.frags[i]
		exStart := ex.offset
		if exStart >= end {
			break
		}
		exEnd := exStart + uint32(len(ex.data)) //nolint:gosec // bounded by caps

		if exStart > pos {
			uStart := pos
			uEnd := min(exStart, end)
			if uEnd > uStart {
				visit(uStart, uEnd)
			}
		}

		if exEnd > pos {
			pos = exEnd
			if pos >= end {
				return
			}
		}
	}

	if pos < end {
		visit(pos, end)
	}
}

// insertMany merges a sorted list of new fragments into the existing sorted list.
func (m *fragments) insertMany(newFrags []*fragment) {
	if len(newFrags) == 0 {
		return
	}

	if len(m.frags) == 0 {
		m.frags = newFrags

		return
	}

	merged := make([]*fragment, 0, len(m.frags)+len(newFrags))
	i := 0 //nolint:varnamelen
	j := 0 //nolint:varnamelen

	for i < len(m.frags) && j < len(newFrags) {
		if m.frags[i].offset < newFrags[j].offset {
			merged = append(merged, m.frags[i])
			i++
		} else {
			merged = append(merged, newFrags[j])
			j++
		}
	}

	if i < len(m.frags) {
		merged = append(merged, m.frags[i:]...)
	}

	if j < len(newFrags) {
		merged = append(merged, newFrags[j:]...)
	}

	m.frags = merged
}

// push attempts to push a DTLS packet to the fragmentBuffer
// when it returns true it means the fragmentBuffer has inserted and the buffer shouldn't be handled
// when an error returns it is fatal, and the DTLS connection should be stopped.
func (f *fragmentBuffer) push(buf []byte) (isHandshake, isRetransmit bool, err error) { //nolint:cyclop,gocognit,gocyclo
	recordLayerHeader := recordlayer.Header{}
	if err := recordLayerHeader.Unmarshal(buf); err != nil {
		return false, false, err
	}

	// fragment isn't a handshake, we don't need to handle it
	if recordLayerHeader.ContentType != protocol.ContentTypeHandshake {
		return false, false, nil
	}

	// enforce "same flight" constraint inside a single record by requiring
	// accepted message_seq values to remain contiguous.
	var flightMin, flightMax uint16
	var flightSet bool

	for buf = buf[recordlayer.FixedHeaderSize:]; len(buf) != 0; {
		var hsHdr handshake.Header
		if err := hsHdr.Unmarshal(buf); err != nil {
			return false, false, err
		}

		// accumulate: a record may contain multiple handshake messages.
		isRetransmit = isRetransmit || (hsHdr.FragmentOffset == 0 && hsHdr.MessageSequence < f.currentMessageSequenceNumber)

		fragLen := hsHdr.FragmentLength
		end := int(handshake.HeaderLength + fragLen)
		if end > len(buf) {
			return false, false, errBufferTooSmall
		}

		seq := hsHdr.MessageSequence
		if seq >= f.currentMessageSequenceNumber { //nolint:nestif
			if !flightSet {
				flightMin, flightMax, flightSet = seq, seq, true
			} else {
				switch {
				case seq < flightMin:
					if flightMin != 0 && seq == flightMin-1 {
						flightMin = seq
					} else {
						buf = buf[end:]

						continue
					}
				case seq > flightMax:
					if seq == flightMax+1 {
						flightMax = seq
					} else {
						buf = buf[end:]

						continue
					}
				}
			}
		}

		// ignore anything older than what we're expecting to pop next.
		if hsHdr.MessageSequence < f.currentMessageSequenceNumber {
			buf = buf[end:]

			continue
		}

		// per-message cap.
		if hsHdr.Length > fragmentBufferMaxSize {
			return false, false, errFragmentBufferOverflow
		}

		// validate fragment range safely (avoid uint32 wraparound).
		fragStart := hsHdr.FragmentOffset

		if fragStart > hsHdr.Length {
			buf = buf[end:]

			continue
		}

		if fragLen > hsHdr.Length-fragStart {
			buf = buf[end:]

			continue
		}

		fragEnd := fragStart + fragLen

		msgSeq := hsHdr.MessageSequence
		messageFragments, ok := f.cache[msgSeq]
		if !ok {
			messageFragments = &fragments{
				frags:           nil,
				handshakeLength: hsHdr.Length,
				epoch:           recordLayerHeader.Epoch,
				baseHeader:      hsHdr,
			}
			f.cache[msgSeq] = messageFragments
		} else {
			// must be consistent across fragments.
			if messageFragments.handshakeLength != hsHdr.Length ||
				messageFragments.baseHeader.MessageSequence != hsHdr.MessageSequence ||
				messageFragments.baseHeader.Type != hsHdr.Type {
				buf = buf[end:]

				continue
			}

			// do not mix epochs for a single handshake message.
			if messageFragments.epoch != recordLayerHeader.Epoch {
				buf = buf[end:]

				continue
			}

			// already complete => nothing to store.
			if messageFragments.receivedLength == messageFragments.handshakeLength {
				buf = buf[end:]

				continue
			}
		}

		payload := buf[handshake.HeaderLength:end]

		// first pass: compute how many unique bytes/chunks to add.
		var addedBytes uint32
		var addedChunks int

		if len(messageFragments.frags) == 0 {
			addedBytes = fragEnd - fragStart
			if addedBytes > 0 {
				addedChunks = 1
			}
		} else {
			messageFragments.scanUncovered(fragStart, fragEnd, func(uStart, uEnd uint32) {
				if uEnd > uStart {
					addedBytes += (uEnd - uStart)
					addedChunks++
				}
			})
		}

		if addedBytes > 0 {
			if f.totalBufferSize+int(addedBytes) > fragmentBufferMaxSize ||
				f.totalFragmentCount+addedChunks > fragmentBufferMaxCount {
				return false, false, errFragmentBufferOverflow
			}

			// one allocation for all bytes to store from this handshake-in-record.
			dataBlob := make([]byte, addedBytes)
			blobOff := uint32(0)

			newFrags := make([]*fragment, 0, addedChunks)

			emit := func(uStart, uEnd uint32) {
				if uEnd <= uStart {
					return
				}
				uLen := uEnd - uStart

				relStart := uStart - fragStart
				relEnd := uEnd - fragStart

				dst := dataBlob[blobOff : blobOff+uLen]
				copy(dst, payload[relStart:relEnd])
				blobOff += uLen

				newFrags = append(newFrags, &fragment{
					offset: uStart,
					data:   dst,
				})
			}

			if len(messageFragments.frags) == 0 {
				emit(fragStart, fragEnd)
			} else {
				messageFragments.scanUncovered(fragStart, fragEnd, emit)
			}

			messageFragments.insertMany(newFrags)

			messageFragments.receivedLength += addedBytes
			f.totalBufferSize += int(addedBytes)
			f.totalFragmentCount += len(newFrags)
		}

		buf = buf[end:]
	}

	return true, isRetransmit, nil
}

func (f *fragmentBuffer) pop() (content []byte, epoch uint16) {
	frags, ok := f.cache[f.currentMessageSequenceNumber]
	if !ok {
		return nil, 0
	}

	if frags.receivedLength != frags.handshakeLength {
		return nil, 0
	}

	// reassemble: stored chunks are non-overlapping and cover the whole message.
	rawMessage := make([]byte, frags.handshakeLength)
	for _, frag := range frags.frags {
		copy(rawMessage[frag.offset:], frag.data)
	}

	firstHeader := frags.baseHeader
	firstHeader.FragmentOffset = 0
	firstHeader.FragmentLength = firstHeader.Length

	rawHeader, err := firstHeader.Marshal()
	if err != nil {
		return nil, 0
	}

	messageEpoch := frags.epoch

	f.totalBufferSize -= int(frags.receivedLength)
	f.totalFragmentCount -= len(frags.frags)

	delete(f.cache, f.currentMessageSequenceNumber)
	f.currentMessageSequenceNumber++

	return append(rawHeader, rawMessage...), messageEpoch
}
