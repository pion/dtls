// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package fragmentbuffer reassembles fragmented DTLS handshake messages.
package fragmentbuffer

import (
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
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
	recordLayerHeader recordlayer.Header
	handshakeHeader   handshake.Header
	data              []byte
}

type fragments struct {
	fragmentByOffset map[uint32]*fragment
	fragmentsLength  uint32
	handshakeLength  uint32
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

// Push attempts to add a DTLS packet to the fragment buffer.
// when it returns true it means the fragmentBuffer has inserted and the buffer shouldn't be handled
// when an error returns it is fatal, and the DTLS connection should be stopped.
func (f *FragmentBuffer) Push(buf []byte) (isHandshake, isRetransmit bool, err error) {
	if f.size()+len(buf) >= fragmentBufferMaxSize || f.totalFragmentCount >= fragmentBufferMaxCount {
		return false, false, dtlserrors.ErrFragmentBufferOverflow
	}

	recordLayerHeader := recordlayer.Header{}
	if err := recordLayerHeader.Unmarshal(buf); err != nil {
		return false, false, err
	}

	// fragment isn't a handshake, we don't need to handle it
	if recordLayerHeader.ContentType != protocol.ContentTypeHandshake {
		return false, false, nil
	}

	headerSize := recordLayerHeader.Size()
	if len(buf) < headerSize {
		return false, false, dtlserrors.ErrBufferTooSmall
	}

	return f.pushHandshakeFragments(recordLayerHeader, buf[headerSize:])
}

func (f *FragmentBuffer) pushHandshakeFragments(
	recordLayerHeader recordlayer.Header,
	buf []byte,
) (isHandshake, isRetransmit bool, err error) {
	for len(buf) != 0 {
		frag := new(fragment)
		if err := frag.handshakeHeader.Unmarshal(buf); err != nil {
			return false, false, err
		}

		// Fragment is a retransmission. We have already assembled it before successfully
		isRetransmit = frag.handshakeHeader.FragmentOffset == 0 &&
			frag.handshakeHeader.MessageSequence < f.currentMessageSequenceNumber

		end := int(handshake.HeaderLength + frag.handshakeHeader.FragmentLength)
		if end > len(buf) {
			return false, false, dtlserrors.ErrBufferTooSmall
		}
		if frag.handshakeHeader.MessageSequence < f.currentMessageSequenceNumber {
			buf = buf[end:]

			continue
		}

		messageFragments, ok := f.cache[frag.handshakeHeader.MessageSequence]
		if !ok {
			messageFragments = &fragments{
				fragmentByOffset: map[uint32]*fragment{}, handshakeLength: frag.handshakeHeader.Length,
			}
			f.cache[frag.handshakeHeader.MessageSequence] = messageFragments
		}

		// Discard all headers, when rebuilding the packet we will re-build
		frag.data = append([]byte{}, buf[handshake.HeaderLength:end]...)
		frag.recordLayerHeader = recordLayerHeader

		if _, ok = messageFragments.fragmentByOffset[frag.handshakeHeader.FragmentOffset]; !ok {
			messageFragments.fragmentByOffset[frag.handshakeHeader.FragmentOffset] = frag
			messageFragments.fragmentsLength += frag.handshakeHeader.FragmentLength
			f.totalBufferSize += int(frag.handshakeHeader.FragmentLength)
			f.totalFragmentCount++
		}
		buf = buf[end:]
	}

	return true, isRetransmit, nil
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

	messageEpoch := frags.fragmentByOffset[0].recordLayerHeader.Epoch

	f.totalBufferSize -= int(frags.fragmentsLength)
	f.totalFragmentCount -= len(frags.fragmentByOffset)

	delete(f.cache, f.currentMessageSequenceNumber)
	f.currentMessageSequenceNumber++

	return append(rawHeader, rawMessage...), messageEpoch
}
