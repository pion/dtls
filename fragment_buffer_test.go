// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFragmentBuffer(t *testing.T) {
	for _, test := range []struct {
		Name     string
		In       [][]byte
		Expected [][]byte
		Epoch    uint16
	}{
		{
			Name: "Single Fragment",
			In: [][]byte{
				{
					0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x03,
					0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xfe, 0xff, 0x00,
				},
			},
			Expected: [][]byte{
				{0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xfe, 0xff, 0x00},
			},
			Epoch: 0,
		},
		{
			Name: "Single Fragment Epoch 3",
			In: [][]byte{
				{
					0x16, 0xfe, 0xff, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x03,
					0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xfe, 0xff, 0x00,
				},
			},
			Expected: [][]byte{
				{0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xfe, 0xff, 0x00},
			},
			Epoch: 3,
		},
		{
			Name: "Multiple Fragments",
			In: [][]byte{
				{
					0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x0b, 0x00,
					0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04,
				},
				{
					0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x0b, 0x00,
					0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x05, 0x05, 0x06, 0x07, 0x08, 0x09,
				},
				{
					0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x0b, 0x00,
					0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x05, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
				},
			},
			Expected: [][]byte{
				{
					0x0b, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
					0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
				},
			},
			Epoch: 0,
		},
		{
			Name: "Multiple Unordered Fragments",
			In: [][]byte{
				{
					0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x0b, 0x00,
					0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04,
				},
				{
					0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x0b, 0x00,
					0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x05, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
				},
				{
					0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x81, 0x0b, 0x00,
					0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x05, 0x05, 0x06, 0x07, 0x08, 0x09,
				},
			},
			Expected: [][]byte{
				{
					0x0b, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x01,
					0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
				},
			},
			Epoch: 0,
		},
		{
			Name: "Multiple Handshakes in Single Fragment",
			In: [][]byte{
				{
					0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x30, /* record header */
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
					0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
					0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x0b, 0x00,
					0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04,
				},
				{
					0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x81, 0x0b, 0x00,
					0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x05, 0x05, 0x06, 0x07, 0x08, 0x09,
				},
			},
			Expected: [][]byte{nil},
			Epoch:    0,
		},
	} {
		fragmentBuffer := newFragmentBuffer()
		for _, frag := range test.In {
			status, _, err := fragmentBuffer.push(frag)
			assert.NoError(t, err)
			assert.Truef(t, status, "fragmentBuffer didn't accept fragments for '%s'", test.Name)
		}

		for _, expected := range test.Expected {
			out, epoch := fragmentBuffer.pop()
			assert.Equalf(t, expected, out, "fragmentBuffer '%s' pop should return expected output", test.Name)
			assert.Equalf(t, test.Epoch, epoch, "fragmentBuffer returend wrong epoch")
		}

		frag, _ := fragmentBuffer.pop()
		assert.Nilf(t, frag, "fragmentBuffer '%s' pop should return nil when no more fragments are available", test.Name)
	}
}

func TestFragmentBuffer_Overflow(t *testing.T) {
	fragmentBuffer := newFragmentBuffer()

	// Push a buffer that doesn't exceed size limits
	_, _, err := fragmentBuffer.push([]byte{
		0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x03,
		0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xfe, 0xff, 0x00,
	})
	assert.NoError(t, err)

	// Allocate a buffer that exceeds cache size
	largeBuffer := make([]byte, fragmentBufferMaxSize)
	_, _, err = fragmentBuffer.push(largeBuffer)
	assert.ErrorIs(t, err, errFragmentBufferOverflow, "Pushing a large buffer should return an overflow error")
}

func TestFragmentBuffer_TooSmall(t *testing.T) {
	fragmentBuffer := newFragmentBuffer()

	// Push a buffer that is smaller than fragment length
	_, _, err := fragmentBuffer.push([]byte{
		0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x03,
		0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xfe, 0xff, 0x00,
	})
	assert.ErrorIs(t, err, errBufferTooSmall,
		"Pushing a buffer that is smaller than fragment length should return an error")
}

func TestFragmentBuffer_UnmarshalInvalid(t *testing.T) {
	fragmentBuffer := newFragmentBuffer()

	// Push a buffer with partial record layer header
	_, _, err := fragmentBuffer.push([]byte{
		0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	assert.Error(t, err, "Pushing a buffer with partial record layer header should return an error")

	// Push a buffer with partial handshake header
	_, _, err = fragmentBuffer.push([]byte{
		0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x03,
	})
	assert.Error(t, err, "Pushing a buffer with partial handshake header should return an error")
}

func testMessageBody(size int) []byte {
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i * 7) //nolint:gosec // Test data.
	}

	return body
}

// handshakeFragmentRecord builds one DTLS record carrying the
// [offset, offset+length) slice of a handshake message body.
func handshakeFragmentRecord(t *testing.T, msgSeq uint16, body []byte, offset, length uint32) []byte {
	t.Helper()

	header := handshake.Header{
		Type:            handshake.TypeCertificate,
		Length:          uint32(len(body)), //nolint:gosec // G115
		MessageSequence: msgSeq,
		FragmentOffset:  offset,
		FragmentLength:  length,
	}
	payload, err := header.Marshal()
	require.NoError(t, err)
	payload = append(payload, body[offset:offset+length]...)

	record := recordlayer.Header{
		ContentType:    protocol.ContentTypeHandshake,
		Version:        protocol.Version1_2,
		ContentLen:     uint16(len(payload)), //nolint:gosec // G115
		SequenceNumber: uint64(msgSeq),
	}
	rawRecord, err := record.Marshal()
	require.NoError(t, err)

	return append(rawRecord, payload...)
}

func reassembledMessage(t *testing.T, body []byte) []byte {
	t.Helper()

	header := handshake.Header{
		Type:           handshake.TypeCertificate,
		Length:         uint32(len(body)), //nolint:gosec // G115
		FragmentLength: uint32(len(body)), //nolint:gosec // G115
	}
	rawHeader, err := header.Marshal()
	require.NoError(t, err)

	return append(rawHeader, body...)
}

func pushFragments(t *testing.T, buffer *fragmentBuffer, body []byte, frags [][2]uint32) {
	t.Helper()

	for _, frag := range frags {
		isHandshake, _, err := buffer.push(handshakeFragmentRecord(t, 0, body, frag[0], frag[1]))
		require.NoError(t, err)
		assert.True(t, isHandshake)
	}
}

// A 700 byte message is sent in 256 byte fragments and the middle one is
// lost. The peer retransmits it in 300 byte fragments, which RFC 6347
// Section 4.2.3 allows, so the message must be reassembled from the two
// differently aligned sets of fragments.
func TestFragmentBuffer_RetransmitWithDifferentBoundaries(t *testing.T) {
	body := testMessageBody(700)
	buffer := newFragmentBuffer()

	pushFragments(t, buffer, body, [][2]uint32{{0, 256}, {512, 188}}) // {256, 256} is lost.
	out, _ := buffer.pop()
	assert.Nil(t, out, "message must not be reassembled while bytes are missing")

	pushFragments(t, buffer, body, [][2]uint32{{0, 300}, {300, 300}, {600, 100}})
	// {0, 300} replaced {0, 256}; {600, 100} was already covered by {512, 188}.
	assert.Equal(t, 300+188+300, buffer.size())
	assert.Equal(t, 3, buffer.totalFragmentCount)

	out, epoch := buffer.pop()
	assert.Equal(t, reassembledMessage(t, body), out)
	assert.Equal(t, uint16(0), epoch)
	assert.Zero(t, buffer.size())
	assert.Zero(t, buffer.totalFragmentCount)

	out, _ = buffer.pop()
	assert.Nil(t, out)
}

func TestFragmentBuffer_OverlappingFragmentsReassemble(t *testing.T) {
	body := testMessageBody(500)
	buffer := newFragmentBuffer()

	// Out of order, overlapping, duplicated, shorter at a cached offset and a
	// strict superset of an earlier fragment.
	pushFragments(t, buffer, body, [][2]uint32{
		{200, 100}, {150, 100}, {200, 100}, {200, 50}, {0, 250}, {400, 100}, {300, 150},
	})

	out, _ := buffer.pop()
	assert.Equal(t, reassembledMessage(t, body), out)
	assert.Zero(t, buffer.size())
	assert.Zero(t, buffer.totalFragmentCount)
}

func TestFragmentBuffer_LongerFragmentReplacesCachedOffset(t *testing.T) {
	body := testMessageBody(10)
	buffer := newFragmentBuffer()

	pushFragments(t, buffer, body, [][2]uint32{{0, 4}, {0, 10}})
	assert.Equal(t, 10, buffer.size())
	assert.Equal(t, 1, buffer.totalFragmentCount)

	out, _ := buffer.pop()
	assert.Equal(t, reassembledMessage(t, body), out)
	assert.Zero(t, buffer.size())
	assert.Zero(t, buffer.totalFragmentCount)
}

func TestFragmentBuffer_OutOfBoundsFragmentIgnored(t *testing.T) {
	body := testMessageBody(100)
	buffer := newFragmentBuffer()

	for _, header := range []handshake.Header{
		{Type: handshake.TypeCertificate, Length: 100, FragmentOffset: 80, FragmentLength: 50}, // Ends past the message.
		{Type: handshake.TypeCertificate, Length: 100, FragmentOffset: 120, FragmentLength: 0}, // Starts past the message.
	} {
		payload, err := header.Marshal()
		require.NoError(t, err)
		payload = append(payload, make([]byte, header.FragmentLength)...)

		record := recordlayer.Header{
			ContentType: protocol.ContentTypeHandshake,
			Version:     protocol.Version1_2,
			ContentLen:  uint16(len(payload)), //nolint:gosec // G115
		}
		rawRecord, err := record.Marshal()
		require.NoError(t, err)

		isHandshake, _, err := buffer.push(append(rawRecord, payload...))
		require.NoError(t, err)
		assert.True(t, isHandshake)
	}
	assert.Zero(t, buffer.size())
	assert.Zero(t, buffer.totalFragmentCount)
	out, _ := buffer.pop()
	assert.Nil(t, out)

	// The valid fragments still complete the message.
	pushFragments(t, buffer, body, [][2]uint32{{0, 60}, {60, 40}})
	out, _ = buffer.pop()
	assert.Equal(t, reassembledMessage(t, body), out)
}

func TestFragmentBuffer_CoveredPrefixBridgesEarlierFragments(t *testing.T) {
	body := testMessageBody(200)
	buffer := newFragmentBuffer()

	// [100, 150) is out of reach until [0, 120) arrives and bridges to it, and
	// the message is only complete once [150, 200) is bridged as well.
	pushFragments(t, buffer, body, [][2]uint32{{100, 50}, {0, 120}})
	out, _ := buffer.pop()
	assert.Nil(t, out)

	pushFragments(t, buffer, body, [][2]uint32{{150, 50}})
	out, _ = buffer.pop()
	assert.Equal(t, reassembledMessage(t, body), out)
	assert.Zero(t, buffer.size())
	assert.Zero(t, buffer.totalFragmentCount)
}

func TestFragmentBuffer_CoveringFragmentReplacesSmallerOnes(t *testing.T) {
	body := testMessageBody(300)
	buffer := newFragmentBuffer()

	pushFragments(t, buffer, body, [][2]uint32{{50, 50}, {100, 50}, {200, 100}})
	assert.Equal(t, 200, buffer.size())
	assert.Equal(t, 3, buffer.totalFragmentCount)

	// Covers the first two entirely and overlaps the third.
	pushFragments(t, buffer, body, [][2]uint32{{0, 250}})
	assert.Equal(t, 350, buffer.size())
	assert.Equal(t, 2, buffer.totalFragmentCount)

	out, _ := buffer.pop()
	assert.Equal(t, reassembledMessage(t, body), out)
	assert.Zero(t, buffer.size())
	assert.Zero(t, buffer.totalFragmentCount)
}

func TestFragmentBuffer_FragmentDisagreeingWithMessageIgnored(t *testing.T) {
	body := testMessageBody(100)

	for name, header := range map[string]handshake.Header{
		// Claims [150, 200) of a longer message: within its own bounds, but
		// beyond the cached message, where it would break reassembly.
		"length": {Type: handshake.TypeCertificate, Length: 300, FragmentOffset: 150, FragmentLength: 50},
		"type":   {Type: handshake.TypeServerHello, Length: 100, FragmentOffset: 50, FragmentLength: 50},
	} {
		t.Run(name, func(t *testing.T) {
			buffer := newFragmentBuffer()
			pushFragments(t, buffer, body, [][2]uint32{{0, 100}})

			payload, err := header.Marshal()
			require.NoError(t, err)
			payload = append(payload, make([]byte, header.FragmentLength)...)

			record := recordlayer.Header{
				ContentType: protocol.ContentTypeHandshake,
				Version:     protocol.Version1_2,
				ContentLen:  uint16(len(payload)), //nolint:gosec // G115
			}
			rawRecord, err := record.Marshal()
			require.NoError(t, err)

			isHandshake, _, err := buffer.push(append(rawRecord, payload...))
			require.NoError(t, err)
			assert.True(t, isHandshake)
			assert.Equal(t, 100, buffer.size())
			assert.Equal(t, 1, buffer.totalFragmentCount)

			out, _ := buffer.pop()
			assert.Equal(t, reassembledMessage(t, body), out)
			assert.Zero(t, buffer.size())
			assert.Zero(t, buffer.totalFragmentCount)
		})
	}
}
