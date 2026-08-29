// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package fragmentbuffer reassembles fragmented DTLS handshake messages.
package fragmentbuffer

import (
	"bytes"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

const (
	// 2 megabytes.
	fragmentBufferMaxSize  = 2000000
	fragmentBufferMaxCount = 1000
)

type fragment struct {
	handshakeHeader handshake.Header
	data            []byte
}

type fragmentKey struct {
	messageSequence uint16
	fragmentOffset  uint32
}

type parsedFragment struct {
	header handshake.Header
	data   []byte
}

type batchMessage struct {
	handshakeType handshake.Type
	length        uint32
	fragments     map[uint32]parsedFragment
}

type fragments struct {
	fragmentByOffset map[uint32]*fragment
	fragmentsLength  uint32
	handshakeLength  uint32
	handshakeType    handshake.Type
	epoch            uint16
}

// FragmentBuffer stores and reassembles fragmented DTLS handshake messages.
type FragmentBuffer struct {
	// map of MessageSequenceNumbers that hold slices of fragments
	cache map[uint16]*fragments

	currentMessageSequenceNumber uint16

	totalBufferSize    int
	totalFragmentCount int
}

// New creates an empty FragmentBuffer.
func New() *FragmentBuffer {
	return &FragmentBuffer{cache: map[uint16]*fragments{}}
}

// current total size of buffer.
func (f *FragmentBuffer) size() int {
	return f.totalBufferSize
}

// AdvanceTo discards fragments for message sequences before messageSequence.
func (f *FragmentBuffer) AdvanceTo(messageSequence uint16) {
	if messageSequence <= f.currentMessageSequenceNumber {
		return
	}

	for cachedSequence, cachedFragments := range f.cache {
		if cachedSequence >= messageSequence {
			continue
		}
		f.totalBufferSize -= int(cachedFragments.fragmentsLength)
		f.totalFragmentCount -= len(cachedFragments.fragmentByOffset)
		delete(f.cache, cachedSequence)
	}

	f.currentMessageSequenceNumber = messageSequence
}

// Push validates and adds handshake fragments from content to the buffer.
// content starts with a handshake header.
func (f *FragmentBuffer) Push(epoch uint16, content []byte) (isRetransmit bool, err error) {
	parsed, err := parseFragments(content)
	if err != nil {
		return false, err
	}
	if err = f.validateFragments(epoch, parsed); err != nil {
		return false, err
	}

	isRetransmit, newFragmentCount, newBufferSize := f.prospectiveResourceUsage(parsed)
	if f.size()+newBufferSize >= fragmentBufferMaxSize ||
		f.totalFragmentCount+newFragmentCount > fragmentBufferMaxCount {
		return false, dtlserrors.ErrFragmentBufferOverflow
	}

	f.commitFragments(epoch, parsed)

	return isRetransmit, nil
}

func parseFragments(content []byte) ([]parsedFragment, error) {
	parsed := make([]parsedFragment, 0)
	for remaining := content; len(remaining) != 0; {
		var header handshake.Header
		if err := header.Unmarshal(remaining); err != nil {
			return nil, err
		}

		end := handshake.HeaderLength + int(header.FragmentLength)
		if end > len(remaining) {
			return nil, dtlserrors.ErrBufferTooSmall
		}
		parsed = append(parsed, parsedFragment{
			header: header,
			data:   remaining[handshake.HeaderLength:end],
		})
		remaining = remaining[end:]
	}

	return parsed, nil
}

func (f *FragmentBuffer) validateFragments(epoch uint16, parsed []parsedFragment) error {
	batch := map[uint16]*batchMessage{}
	for _, candidate := range parsed {
		if err := validateFragmentBounds(candidate.header); err != nil {
			return err
		}
		if err := f.validateCachedFragment(epoch, candidate); err != nil {
			return err
		}
		if err := validateBatchFragment(batch, candidate); err != nil {
			return err
		}
	}

	return nil
}

func validateFragmentBounds(header handshake.Header) error {
	if header.FragmentOffset > header.Length ||
		header.FragmentLength > header.Length-header.FragmentOffset {
		return dtlserrors.ErrInvalidPacket
	}

	return nil
}

func (f *FragmentBuffer) validateCachedFragment(epoch uint16, candidate parsedFragment) error {
	header := candidate.header
	cached, ok := f.cache[header.MessageSequence]
	if !ok {
		return nil
	}
	if cached.handshakeType != header.Type ||
		cached.handshakeLength != header.Length ||
		cached.epoch != epoch {
		return dtlserrors.ErrInvalidPacket
	}

	for _, existing := range cached.fragmentByOffset {
		if err := validateFragmentPair(
			existing.handshakeHeader,
			existing.data,
			header,
			candidate.data,
		); err != nil {
			return err
		}
	}

	return nil
}

func validateBatchFragment(batch map[uint16]*batchMessage, candidate parsedFragment) error {
	header := candidate.header
	message, ok := batch[header.MessageSequence]
	if !ok {
		batch[header.MessageSequence] = &batchMessage{handshakeType: header.Type, length: header.Length, fragments: map[uint32]parsedFragment{header.FragmentOffset: candidate}}

		return nil
	}
	if message.handshakeType != header.Type || message.length != header.Length {
		return dtlserrors.ErrInvalidPacket
	}

	for _, existing := range message.fragments {
		if err := validateFragmentPair(existing.header, existing.data, header, candidate.data); err != nil {
			return err
		}
	}
	if _, ok = message.fragments[header.FragmentOffset]; !ok {
		message.fragments[header.FragmentOffset] = candidate
	}

	return nil
}

func validateFragmentPair(existingHeader handshake.Header, existingData []byte, candidateHeader handshake.Header, candidateData []byte) error {
	if existingHeader.FragmentOffset == candidateHeader.FragmentOffset {
		if existingHeader != candidateHeader || !bytes.Equal(existingData, candidateData) {
			return dtlserrors.ErrInvalidPacket
		}

		return nil
	}

	existingEnd := existingHeader.FragmentOffset + existingHeader.FragmentLength
	candidateEnd := candidateHeader.FragmentOffset + candidateHeader.FragmentLength
	if existingHeader.FragmentOffset < candidateEnd && candidateHeader.FragmentOffset < existingEnd {
		return dtlserrors.ErrInvalidPacket
	}

	return nil
}

func (f *FragmentBuffer) prospectiveResourceUsage(parsed []parsedFragment) (isRetransmit bool, newFragmentCount int, newBufferSize int) {
	newFragments := map[fragmentKey]struct{}{}
	for _, candidate := range parsed {
		header := candidate.header
		if header.MessageSequence < f.currentMessageSequenceNumber {
			isRetransmit = true

			continue
		}

		if messageFragments, ok := f.cache[header.MessageSequence]; ok {
			if _, ok = messageFragments.fragmentByOffset[header.FragmentOffset]; ok {
				continue
			}
		}

		key := fragmentKey{
			messageSequence: header.MessageSequence,
			fragmentOffset:  header.FragmentOffset,
		}
		if _, ok := newFragments[key]; !ok {
			newFragments[key] = struct{}{}
			newFragmentCount++
			newBufferSize += int(header.FragmentLength)
		}
	}

	return isRetransmit, newFragmentCount, newBufferSize
}

func (f *FragmentBuffer) commitFragments(epoch uint16, parsed []parsedFragment) {
	for _, candidate := range parsed {
		header := candidate.header
		if header.MessageSequence < f.currentMessageSequenceNumber {
			continue
		}

		messageFragments, ok := f.cache[header.MessageSequence]
		if !ok {
			messageFragments = &fragments{fragmentByOffset: map[uint32]*fragment{}, handshakeLength: header.Length, handshakeType: header.Type, epoch: epoch}
			f.cache[header.MessageSequence] = messageFragments
		}
		if _, ok = messageFragments.fragmentByOffset[header.FragmentOffset]; !ok {
			messageFragments.fragmentByOffset[header.FragmentOffset] = &fragment{handshakeHeader: header, data: bytes.Clone(candidate.data)}
			messageFragments.fragmentsLength += header.FragmentLength
			f.totalBufferSize += int(header.FragmentLength)
			f.totalFragmentCount++
		}
	}
}

// Pop returns the next complete handshake message and its record epoch.
func (f *FragmentBuffer) Pop() (content []byte, epoch uint16) {
	frags, ok := f.cache[f.currentMessageSequenceNumber]
	if !ok {
		return nil, 0
	}

	if frags.fragmentsLength != frags.handshakeLength {
		return nil, 0
	}

	var rawMessage []byte
	targetOffset := uint32(0)
	for i := 0; i < len(frags.fragmentByOffset) && targetOffset < frags.handshakeLength; i++ {
		if frag, ok := frags.fragmentByOffset[targetOffset]; ok {
			rawMessage = append(rawMessage, frag.data...)
			targetOffset = frag.handshakeHeader.FragmentOffset + frag.handshakeHeader.FragmentLength
		} else {
			return nil, 0
		}
	}

	if int(frags.handshakeLength) != len(rawMessage) {
		return nil, 0
	}

	firstHeader := frags.fragmentByOffset[0].handshakeHeader
	firstHeader.FragmentOffset = 0
	firstHeader.FragmentLength = firstHeader.Length

	rawHeader, _ := firstHeader.Marshal()

	messageEpoch := frags.epoch

	f.totalBufferSize -= int(frags.fragmentsLength)
	f.totalFragmentCount -= len(frags.fragmentByOffset)

	delete(f.cache, f.currentMessageSequenceNumber)
	f.currentMessageSequenceNumber++

	return append(rawHeader, rawMessage...), messageEpoch
}
