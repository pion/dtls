// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"slices"
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

// fragmentRange is the payload of one handshake fragment.
type fragmentRange struct {
	offset uint32
	data   []byte
}

func (r fragmentRange) end() uint32 {
	return r.offset + uint32(len(r.data)) //nolint:gosec // G115: fragment lengths are 24 bit.
}

// fragments holds what has been received of one handshake message. A peer may
// fragment a retransmitted message differently from the original transmission
// (RFC 6347 Section 4.2.3), so fragments can overlap. ranges is sorted by
// offset and never holds a fragment that another one fully covers, which
// makes its ends increase as well; covered is the length of the contiguous
// prefix of the message received so far and is advanced as fragments arrive,
// so completeness is known without scanning.
type fragments struct {
	ranges          []fragmentRange
	covered         uint32
	handshakeType   handshake.Type
	handshakeLength uint32
	// From the first fragment received at offset 0.
	handshakeHeader handshake.Header
	epoch           uint16
	hasStart        bool
}

// add stores a fragment and returns the change in stored fragment count and
// bytes, which is negative when the fragment replaces smaller ones.
func (f *fragments) add(offset uint32, data []byte) (fragmentDelta, byteDelta int) {
	frag := fragmentRange{offset: offset, data: data}

	// First fragment starting at or after offset.
	i := sort.Search(len(f.ranges), func(k int) bool { return f.ranges[k].offset >= offset })
	if f.covers(i, frag) {
		return 0, 0
	}

	// ranges[i:j] start inside the new fragment and end inside it: covered.
	j := i
	for j < len(f.ranges) && f.ranges[j].end() <= frag.end() {
		fragmentDelta--
		byteDelta -= len(f.ranges[j].data)
		j++
	}
	f.ranges = slices.Replace(f.ranges, i, j, frag)
	f.advanceCovered(i)

	return fragmentDelta + 1, byteDelta + len(data)
}

// covers reports whether a stored fragment already carries every byte of
// frag, whose insertion index is i. Since ends increase with offsets, only
// the fragment before i and one starting at the same offset can.
func (f *fragments) covers(i int, frag fragmentRange) bool {
	if i > 0 && f.ranges[i-1].end() >= frag.end() {
		return true
	}

	return i < len(f.ranges) && f.ranges[i].offset == frag.offset && f.ranges[i].end() >= frag.end()
}

// advanceCovered extends the covered prefix after inserting ranges[i]. Only
// a fragment touching the prefix can extend it, possibly through fragments
// received earlier that start within its reach.
func (f *fragments) advanceCovered(i int) {
	if f.ranges[i].offset > f.covered {
		return
	}
	for k := i; k < len(f.ranges) && f.ranges[k].offset <= f.covered; k++ {
		f.covered = max(f.covered, f.ranges[k].end())
	}
}

type fragmentBuffer struct {
	// map of MessageSequenceNumbers that hold slices of fragments
	cache map[uint16]*fragments

	currentMessageSequenceNumber uint16

	totalBufferSize    int
	totalFragmentCount int
}

func newFragmentBuffer() *fragmentBuffer {
	return &fragmentBuffer{cache: map[uint16]*fragments{}}
}

// current total size of buffer.
func (f *fragmentBuffer) size() int {
	return f.totalBufferSize
}

// Attempts to push a DTLS packet to the fragmentBuffer
// when it returns true it means the fragmentBuffer has inserted and the buffer shouldn't be handled
// when an error returns it is fatal, and the DTLS connection should be stopped.
// The fragments keep referencing buf, so it must not be reused by the caller.
func (f *fragmentBuffer) push(buf []byte) (isHandshake, isRetransmit bool, err error) { //nolint:cyclop
	if f.size()+len(buf) >= fragmentBufferMaxSize || f.totalFragmentCount >= fragmentBufferMaxCount {
		return false, false, errFragmentBufferOverflow
	}

	recordLayerHeader := recordlayer.Header{}
	if err := recordLayerHeader.Unmarshal(buf); err != nil {
		return false, false, err
	}

	// fragment isn't a handshake, we don't need to handle it
	if recordLayerHeader.ContentType != protocol.ContentTypeHandshake {
		return false, false, nil
	}

	for buf = buf[recordlayer.FixedHeaderSize:]; len(buf) != 0; { //nolint:gosec // G602
		var header handshake.Header
		if err := header.Unmarshal(buf); err != nil {
			return false, false, err
		}

		// Fragment is a retransmission. We have already assembled it before successfully
		isRetransmit = header.FragmentOffset == 0 && header.MessageSequence < f.currentMessageSequenceNumber

		end := int(handshake.HeaderLength + header.FragmentLength)
		if end > len(buf) {
			return false, false, errBufferTooSmall
		}
		data := buf[handshake.HeaderLength:end]
		buf = buf[end:]

		// Already assembled, or claims bytes outside the message.
		if header.MessageSequence < f.currentMessageSequenceNumber ||
			header.FragmentOffset > header.Length ||
			header.FragmentLength > header.Length-header.FragmentOffset {
			continue
		}

		messageFragments, ok := f.cache[header.MessageSequence]
		if !ok {
			messageFragments = &fragments{handshakeType: header.Type, handshakeLength: header.Length}
			f.cache[header.MessageSequence] = messageFragments
		} else if header.Type != messageFragments.handshakeType || header.Length != messageFragments.handshakeLength {
			// Disagrees with the message's earlier fragments; admitting it
			// would break the bounds pop relies on.
			continue
		}
		if header.FragmentOffset == 0 && !messageFragments.hasStart {
			messageFragments.handshakeHeader = header
			messageFragments.epoch = recordLayerHeader.Epoch
			messageFragments.hasStart = true
		}
		if len(data) == 0 {
			continue
		}

		fragmentDelta, byteDelta := messageFragments.add(header.FragmentOffset, data)
		f.totalFragmentCount += fragmentDelta
		f.totalBufferSize += byteDelta
	}

	return true, isRetransmit, nil
}

func (f *fragmentBuffer) pop() (content []byte, epoch uint16) {
	frags, ok := f.cache[f.currentMessageSequenceNumber]
	if !ok || frags.covered < frags.handshakeLength {
		return nil, 0
	}

	firstHeader := frags.handshakeHeader
	firstHeader.FragmentOffset = 0
	firstHeader.FragmentLength = firstHeader.Length

	rawHeader, _ := firstHeader.Marshal()

	// The message is contiguous, so each fragment continues at or before
	// where the previous one ended.
	content = make([]byte, 0, len(rawHeader)+int(frags.handshakeLength))
	content = append(content, rawHeader...)
	cursor := uint32(0)
	for _, frag := range frags.ranges {
		content = append(content, frag.data[cursor-frag.offset:]...)
		cursor = frag.end()
		f.totalBufferSize -= len(frag.data)
	}
	f.totalFragmentCount -= len(frags.ranges)

	delete(f.cache, f.currentMessageSequenceNumber)
	f.currentMessageSequenceNumber++

	return content, frags.epoch
}
