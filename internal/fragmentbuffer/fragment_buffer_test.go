// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package fragmentbuffer

import (
	"testing"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFragmentBuffer(t *testing.T) {
	single := []byte{0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xfe, 0xff, 0x00}
	fragment := func(offset byte) []byte {
		return []byte{
			0x0b, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, offset, 0x00, 0x00, 0x05,
			offset, offset + 1, offset + 2, offset + 3, offset + 4,
		}
	}
	fragments := [][]byte{fragment(0), fragment(5), fragment(10)}
	reassembled := [][]byte{{
		0x0b, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
	}}
	for _, test := range []struct {
		Name     string
		In       [][]byte
		Expected [][]byte
		Epoch    uint16
	}{
		{
			Name: "Single Fragment", In: [][]byte{single}, Expected: [][]byte{single}, Epoch: 0,
		},
		{
			Name: "Single Fragment Epoch 3", In: [][]byte{single}, Expected: [][]byte{single}, Epoch: 3,
		},
		{
			Name: "Multiple Fragments", In: fragments, Expected: reassembled, Epoch: 0,
		},
		{
			Name: "Multiple Unordered Fragments", In: [][]byte{fragments[0], fragments[2], fragments[1]}, Expected: reassembled, Epoch: 0, //nolint:lll
		},
		{
			Name: "Multiple Handshakes in Single Fragment",
			In: [][]byte{
				{
					0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff, 0x01, 0x01, /*handshake msg 1*/
					0x03, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff, 0x01, 0x01, /*handshake msg 2*/
					0x03, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff, 0x01, 0x01, /*handshake msg 3*/
				},
			},
			Expected: [][]byte{
				{0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff, 0x01, 0x01},
				{0x03, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff, 0x01, 0x01},
				{0x03, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff, 0x01, 0x01},
			},
			Epoch: 0,
		},
		// Assert that a zero length fragment doesn't cause the fragmentBuffer to enter an infinite loop
		{
			Name: "Zero Length Fragment",
			In: [][]byte{
				{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				},
			},
			Expected: [][]byte{
				{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			},
			Epoch: 0,
		},
		// Not aligned fragments should not be reassembled
		{
			Name: "Not Aligned Fragments",
			In: [][]byte{
				{
					0x0b, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
					0x00, 0x01, 0x02, 0x03, 0x04,
				},
				{
					0x0b, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x05,
					0x05, 0x06, 0x07, 0x08, 0x09,
				},
			},
			Expected: [][]byte{nil},
			Epoch:    0,
		},
	} {
		fragmentBuffer := New()
		for _, frag := range test.In {
			_, err := fragmentBuffer.Push(test.Epoch, frag)
			assert.NoError(t, err)
		}

		for _, expected := range test.Expected {
			out, epoch := fragmentBuffer.Pop()
			assert.Equalf(t, expected, out, "fragmentBuffer '%s' pop should return expected output", test.Name)
			assert.Equalf(t, test.Epoch, epoch, "fragmentBuffer returend wrong epoch")
		}

		frag, _ := fragmentBuffer.Pop()
		assert.Nilf(t, frag, "fragmentBuffer '%s' pop should return nil when no more fragments are available", test.Name)
	}
}

func TestFragmentBuffer_Overflow(t *testing.T) {
	fragmentBuffer := New()

	small := marshalHandshakeContent(t, handshake.Header{
		Type:           handshake.TypeHelloVerifyRequest,
		Length:         3,
		FragmentLength: 3,
	})
	_, err := fragmentBuffer.Push(0, small)
	require.NoError(t, err)

	large := marshalHandshakeContent(t, handshake.Header{
		Type:            handshake.TypeCertificate,
		Length:          fragmentBufferMaxSize,
		MessageSequence: 1,
		FragmentLength:  fragmentBufferMaxSize,
	})
	_, err = fragmentBuffer.Push(0, large)
	assert.ErrorIs(t, err, dtlserrors.ErrFragmentBufferOverflow,
		"Pushing a large buffer should return an overflow error")

	content, epoch := fragmentBuffer.Pop()
	assert.Equal(t, small, content)
	assert.Equal(t, uint16(0), epoch)
	content, _ = fragmentBuffer.Pop()
	assert.Nil(t, content)
}

func TestFragmentBuffer_TooSmall(t *testing.T) {
	fragmentBuffer := New()

	_, err := fragmentBuffer.Push(0, []byte{
		0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
		0xfe, 0xff, 0x00,
	})
	assert.ErrorIs(t, err, dtlserrors.ErrBufferTooSmall,
		"Pushing a buffer that is smaller than fragment length should return an error")
}

func TestFragmentBuffer_UnmarshalInvalidHandshake(t *testing.T) {
	fragmentBuffer := New()

	_, err := fragmentBuffer.Push(0, []byte{0x03})
	assert.Error(t, err, "Pushing a buffer with partial handshake header should return an error")
}

func TestFragmentBuffer_InvalidBatchDoesNotCommit(t *testing.T) {
	fragmentBuffer := New()
	valid := marshalHandshakeContent(t, handshake.Header{
		Type:           handshake.TypeCertificate,
		Length:         1,
		FragmentLength: 1,
	})
	batch := append(append([]byte{}, valid...), 0x03)

	_, err := fragmentBuffer.Push(0, batch)
	require.Error(t, err)
	assert.Empty(t, fragmentBuffer.cache)
	assert.Zero(t, fragmentBuffer.totalBufferSize)
	assert.Zero(t, fragmentBuffer.totalFragmentCount)
}

func TestFragmentBuffer_InvalidFragmentDoesNotMutateCache(t *testing.T) {
	baseHeader := handshake.Header{
		Type:           handshake.TypeCertificate,
		Length:         4,
		FragmentLength: 2,
	}
	completionHeader := baseHeader
	completionHeader.FragmentOffset = 2

	tests := []struct {
		name      string
		epoch     uint16
		header    handshake.Header
		alterData bool
	}{
		{
			name:   "cross epoch",
			epoch:  8,
			header: completionHeader,
		},
		{
			name:  "type mismatch",
			epoch: 7,
			header: func() handshake.Header {
				header := completionHeader
				header.Type = handshake.TypeClientHello

				return header
			}(),
		},
		{
			name:  "length mismatch",
			epoch: 7,
			header: func() handshake.Header {
				header := completionHeader
				header.Length = 5

				return header
			}(),
		},
		{
			name:  "out of bounds",
			epoch: 7,
			header: func() handshake.Header {
				header := completionHeader
				header.FragmentOffset = 3

				return header
			}(),
		},
		{
			name:  "overlap",
			epoch: 7,
			header: func() handshake.Header {
				header := completionHeader
				header.FragmentOffset = 1

				return header
			}(),
		},
		{
			name:      "conflicting duplicate",
			epoch:     7,
			header:    baseHeader,
			alterData: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fragmentBuffer := New()
			base := marshalHandshakeContent(t, baseHeader)
			_, err := fragmentBuffer.Push(7, base)
			require.NoError(t, err)

			candidate := marshalHandshakeContent(t, test.header)
			if test.alterData {
				candidate[len(candidate)-1] = 1
			}
			_, err = fragmentBuffer.Push(test.epoch, candidate)
			assert.ErrorIs(t, err, dtlserrors.ErrInvalidPacket)
			assert.Equal(t, 2, fragmentBuffer.totalBufferSize)
			assert.Equal(t, 1, fragmentBuffer.totalFragmentCount)
			require.Len(t, fragmentBuffer.cache, 1)
			assert.Equal(t, base[handshake.HeaderLength:], fragmentBuffer.cache[0].fragmentByOffset[0].data)

			_, err = fragmentBuffer.Push(7, marshalHandshakeContent(t, completionHeader))
			require.NoError(t, err)
			content, epoch := fragmentBuffer.Pop()
			expectedHeader := baseHeader
			expectedHeader.FragmentLength = expectedHeader.Length
			assert.Equal(t, marshalHandshakeContent(t, expectedHeader), content)
			assert.Equal(t, uint16(7), epoch)
		})
	}
}

func TestFragmentBuffer_InvalidMetadataWithinBatchDoesNotCommit(t *testing.T) {
	fragmentBuffer := New()
	first := handshake.Header{
		Type:           handshake.TypeCertificate,
		Length:         4,
		FragmentLength: 2,
	}
	second := first
	second.Type = handshake.TypeClientHello
	second.FragmentOffset = 2

	_, err := fragmentBuffer.Push(7, marshalHandshakeContent(t, first, second))
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidPacket)
	assert.Empty(t, fragmentBuffer.cache)
	assert.Zero(t, fragmentBuffer.totalBufferSize)
	assert.Zero(t, fragmentBuffer.totalFragmentCount)
}

func TestFragmentBuffer_OverlapWithinBatchDoesNotCommit(t *testing.T) {
	fragmentBuffer := New()
	first := handshake.Header{
		Type:           handshake.TypeCertificate,
		Length:         4,
		FragmentLength: 3,
	}
	second := first
	second.FragmentOffset = 2
	second.FragmentLength = 2

	_, err := fragmentBuffer.Push(7, marshalHandshakeContent(t, first, second))
	assert.ErrorIs(t, err, dtlserrors.ErrInvalidPacket)
	assert.Empty(t, fragmentBuffer.cache)
	assert.Zero(t, fragmentBuffer.totalBufferSize)
	assert.Zero(t, fragmentBuffer.totalFragmentCount)
}

func TestFragmentBuffer_ExactDuplicateDoesNotConsumeResources(t *testing.T) {
	fragmentBuffer := New()
	headers := make([]handshake.Header, fragmentBufferMaxCount)
	for i := range headers {
		headers[i] = handshake.Header{
			Type:            handshake.TypeCertificate,
			MessageSequence: uint16(i), //nolint:gosec // The test count is bounded to 1000.
		}
	}
	content := marshalHandshakeContent(t, headers...)

	_, err := fragmentBuffer.Push(7, content)
	require.NoError(t, err)
	assert.Equal(t, fragmentBufferMaxCount, fragmentBuffer.totalFragmentCount)
	assert.Zero(t, fragmentBuffer.totalBufferSize)

	isRetransmit, err := fragmentBuffer.Push(7, marshalHandshakeContent(t, headers[0]))
	require.NoError(t, err)
	assert.False(t, isRetransmit)
	assert.Equal(t, fragmentBufferMaxCount, fragmentBuffer.totalFragmentCount)
	assert.Zero(t, fragmentBuffer.totalBufferSize)
}

func TestFragmentBuffer_CountOverflowDoesNotCommit(t *testing.T) {
	fragmentBuffer := New()
	headers := make([]handshake.Header, fragmentBufferMaxCount+1)
	for i := range headers {
		headers[i] = handshake.Header{
			Type:            handshake.TypeCertificate,
			MessageSequence: uint16(i), //nolint:gosec // The test count is bounded to 1001.
		}
	}

	_, err := fragmentBuffer.Push(0, marshalHandshakeContent(t, headers...))
	assert.ErrorIs(t, err, dtlserrors.ErrFragmentBufferOverflow)
	assert.Empty(t, fragmentBuffer.cache)
	assert.Zero(t, fragmentBuffer.totalBufferSize)
	assert.Zero(t, fragmentBuffer.totalFragmentCount)
}

func TestFragmentBuffer_ClonesRetainedPayload(t *testing.T) {
	fragmentBuffer := New()
	content := marshalHandshakeContent(t, handshake.Header{
		Type:           handshake.TypeCertificate,
		Length:         1,
		FragmentLength: 1,
	})
	content[len(content)-1] = 0xaa
	expected := append([]byte{}, content...)

	_, err := fragmentBuffer.Push(7, content)
	require.NoError(t, err)
	content[len(content)-1] = 0xbb

	actual, epoch := fragmentBuffer.Pop()
	assert.Equal(t, expected, actual)
	assert.Equal(t, uint16(7), epoch)
}

func TestFragmentBuffer_RetransmitDetection(t *testing.T) {
	tests := []struct {
		name               string
		headers            []handshake.Header
		expectedRetransmit bool
	}{
		{
			name: "old nonzero-offset fragment",
			headers: []handshake.Header{{
				Type:            handshake.TypeCertificate,
				Length:          2,
				MessageSequence: 0,
				FragmentOffset:  1,
				FragmentLength:  1,
			}},
			expectedRetransmit: true,
		},
		{
			name: "old fragment followed by current fragment",
			headers: []handshake.Header{
				{
					Type:            handshake.TypeCertificate,
					Length:          1,
					MessageSequence: 0,
					FragmentLength:  1,
				},
				{
					Type:            handshake.TypeCertificate,
					Length:          1,
					MessageSequence: 1,
					FragmentLength:  1,
				},
			},
			expectedRetransmit: true,
		},
		{
			name: "current fragment",
			headers: []handshake.Header{{
				Type:            handshake.TypeCertificate,
				Length:          1,
				MessageSequence: 1,
				FragmentLength:  1,
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fragmentBuffer := New()
			fragmentBuffer.AdvanceTo(1)

			isRetransmit, err := fragmentBuffer.Push(0, marshalHandshakeContent(t, test.headers...))
			require.NoError(t, err)
			assert.Equal(t, test.expectedRetransmit, isRetransmit)
		})
	}
}

func marshalHandshakeContent(t *testing.T, headers ...handshake.Header) []byte {
	t.Helper()

	var content []byte
	for i := range headers {
		rawHeader, err := headers[i].Marshal()
		require.NoError(t, err)
		content = append(content, rawHeader...)
		content = append(content, make([]byte, headers[i].FragmentLength)...)
	}

	return content
}
