// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package handshake

import (
	"testing"
	"time"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/stretchr/testify/assert"
)

type mismatchedExtension struct{}

func (mismatchedExtension) ExtensionType() extension.Type { return extension.TypePadding }
func (mismatchedExtension) MarshalSize() int              { return 1 }
func (mismatchedExtension) MarshalData() ([]byte, error)  { return nil, nil }

type unexpectedMarshalExtension struct {
	sizeCalls int
	dataCalls int
}

func (*unexpectedMarshalExtension) ExtensionType() extension.Type { return extension.TypePadding }

func (e *unexpectedMarshalExtension) MarshalSize() int {
	e.sizeCalls++

	return 0
}

func (e *unexpectedMarshalExtension) MarshalData() ([]byte, error) {
	e.dataCalls++

	return nil, nil
}

func TestHelloMarshalValidatesFieldsBeforePreparingExtensions(t *testing.T) {
	cipherSuiteID := uint16(0xc02b)
	compressionMethod := &protocol.CompressionMethod{}
	unexpectedExtension := &unexpectedMarshalExtension{}
	extensions := []extension.Value{unexpectedExtension}

	tests := []struct {
		name    string
		message Message
		err     error
	}{
		{
			name:    "client cookie",
			message: &MessageClientHello{Cookie: make([]byte, 256), extensions: extensions},
			err:     dtlserrors.ErrCookieTooLong,
		},
		{
			name:    "client session ID",
			message: &MessageClientHello{SessionID: make([]byte, 256), extensions: extensions},
			err:     dtlserrors.ErrSessionIDTooLong,
		},
		{
			name: "client compression methods",
			message: &MessageClientHello{
				CompressionMethods: make([]*protocol.CompressionMethod, 256),
				extensions:         extensions,
			},
			err: dtlserrors.ErrCompressionMethodsTooLong,
		},
		{
			name:    "server cipher suite",
			message: &MessageServerHello{CompressionMethod: compressionMethod, extensions: extensions},
			err:     dtlserrors.ErrCipherSuiteUnset,
		},
		{
			name: "server compression method",
			message: &MessageServerHello{
				CipherSuiteID: &cipherSuiteID,
				extensions:    extensions,
			},
			err: dtlserrors.ErrCompressionMethodUnset,
		},
		{
			name: "server session ID",
			message: &MessageServerHello{
				SessionID:         make([]byte, 256),
				CipherSuiteID:     &cipherSuiteID,
				CompressionMethod: compressionMethod,
				extensions:        extensions,
			},
			err: dtlserrors.ErrSessionIDTooLong,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := test.message.Marshal()
			assert.Nil(t, encoded)
			assert.ErrorIs(t, err, test.err)
			assert.Zero(t, unexpectedExtension.sizeCalls)
			assert.Zero(t, unexpectedExtension.dataCalls)
		})
	}
}

func TestMessageServerHelloExtensionFramingErrorIsClassified(t *testing.T) {
	cipherSuiteID := uint16(0xc02b)
	raw, err := (&MessageServerHello{
		Version:           protocol.Version1_2,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: &protocol.CompressionMethod{},
	}).Marshal()
	assert.NoError(t, err)
	raw[len(raw)-1] = 1

	err = (&MessageServerHello{}).Unmarshal(raw)
	assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
	var got *alert.Alert
	assert.ErrorAs(t, err, &got)
	assert.Equal(t, alert.DecodeError, got.Description)
}

func TestMessageServerHelloRejectsHelloRetryRequestWithoutSupportedVersions(t *testing.T) {
	var randomFixed [RandomLength]byte
	copy(randomFixed[:], HelloRetryRequestRandom())
	var random Random
	random.UnmarshalFixed(randomFixed)
	cipherSuiteID := uint16(0x1301)
	raw, err := (&MessageServerHello{
		Version:           protocol.Version1_2,
		Random:            random,
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: &protocol.CompressionMethod{},
	}).Marshal()
	assert.NoError(t, err)

	for name, input := range map[string][]byte{
		"empty vector":   raw,
		"omitted vector": raw[:len(raw)-2],
	} {
		t.Run(name, func(t *testing.T) {
			err := (&MessageServerHello{}).Unmarshal(input)
			assert.ErrorIs(t, err, dtlserrors.ErrMissingSupportedVersionsExtension)
			var got *alert.Alert
			assert.ErrorAs(t, err, &got)
			assert.Equal(t, alert.MissingExtension, got.Description)
		})
	}
}

func TestHandshakeMessageServerHello(t *testing.T) {
	rawServerHello := []byte{
		0xfe, 0xfd, 0x21, 0x63, 0x32, 0x21, 0x81, 0x0e, 0x98, 0x6c,
		0x85, 0x3d, 0xa4, 0x39, 0xaf, 0x5f, 0xd6, 0x5c, 0xcc, 0x20,
		0x7f, 0x7c, 0x78, 0xf1, 0x5f, 0x7e, 0x1c, 0xb7, 0xa1, 0x1e,
		0xcf, 0x63, 0x84, 0x28, 0x00, 0xc0, 0x2b, 0x00, 0x00, 0x00,
	}

	cipherSuiteID := uint16(0xc02b)

	parsedServerHello := &MessageServerHello{
		Version: protocol.Version{Major: 0xFE, Minor: 0xFD},
		Random: Random{
			GMTUnixTime: time.Unix(560149025, 0),
			RandomBytes: [28]byte{
				0x81, 0x0e, 0x98, 0x6c, 0x85, 0x3d, 0xa4, 0x39, 0xaf, 0x5f, 0xd6, 0x5c, 0xcc, 0x20,
				0x7f, 0x7c, 0x78, 0xf1, 0x5f, 0x7e, 0x1c, 0xb7, 0xa1, 0x1e, 0xcf, 0x63, 0x84, 0x28,
			},
		},
		SessionID:         []byte{},
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: &protocol.CompressionMethod{},
		extensions:        []extension.Value{},
	}

	c := &MessageServerHello{}
	assert.NoError(t, c.Unmarshal(rawServerHello))
	assert.Equal(t, parsedServerHello, c, "handshakeMessageServerHello mismatch")

	raw, err := c.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawServerHello, raw, "handshakeMessageServerHello mismatch")
}

func TestHandshakeMessageServerHelloSessionID(t *testing.T) {
	rawServerHello := []byte{
		0xfe, 0xfd, 0x21, 0x63, 0x32, 0x21, 0x81, 0x0e, 0x98, 0x6c,
		0x85, 0x3d, 0xa4, 0x39, 0xaf, 0x5f, 0xd6, 0x5c, 0xcc, 0x20,
		0x7f, 0x7c, 0x78, 0xf1, 0x5f, 0x7e, 0x1c, 0xb7, 0xa1, 0x1e,
		0xcf, 0x63, 0x84, 0x28, 0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4,
		0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee,
		0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
		0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0xc0, 0x2b, 0x00,
		0x00, 0x00,
	}

	sessionID := []byte{
		0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
		0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3,
		0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
		0xfe, 0xff,
	}

	c := &MessageServerHello{}
	assert.NoError(t, c.Unmarshal(rawServerHello))
	assert.Equal(t, sessionID, c.SessionID, "handshakeMessageServerHello invalid SessionID")

	raw, err := c.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, rawServerHello, raw, "handshakeMessageServerHello mismatch")
}

func TestHandshakeMessageServerHello_SessionIDTooLong(t *testing.T) {
	cipherSuiteID := uint16(0xc02b)
	c := &MessageServerHello{
		Version:           protocol.Version{Major: 0xFE, Minor: 0xFD},
		SessionID:         make([]byte, 256),
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: &protocol.CompressionMethod{ID: 0},
		extensions:        []extension.Value{},
	}

	_, err := c.Marshal()
	assert.ErrorIs(t, err, dtlserrors.ErrSessionIDTooLong)
}

func TestExtensionMessagesRejectMismatchedPayloadSize(t *testing.T) {
	extensions := []extension.Value{mismatchedExtension{}}
	cipherSuiteID := uint16(0xc02b)

	tests := map[string]Message{
		"client hello": &MessageClientHello{extensions: extensions},
		"server hello": &MessageServerHello{
			CipherSuiteID:     &cipherSuiteID,
			CompressionMethod: &protocol.CompressionMethod{},
			extensions:        extensions,
		},
		"encrypted extensions": &MessageEncryptedExtensions{extensions: extensions},
	}

	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			encoded, err := message.Marshal()
			assert.Nil(t, encoded)
			assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
		})
	}
}

func TestMessageServerHelloMarshalToReportsActualExtensionCount(t *testing.T) {
	cipherSuiteID := uint16(0xc02b)
	message := &MessageServerHello{
		CipherSuiteID:     &cipherSuiteID,
		CompressionMethod: &protocol.CompressionMethod{},
		extensions:        []extension.Value{mismatchedExtension{}},
	}

	n, err := message.MarshalTo(make([]byte, message.MarshalSize()))
	message.SetExtensions(nil)
	assert.Equal(t, message.MarshalSize(), n)
	assert.ErrorIs(t, err, dtlserrors.ErrLengthMismatch)
}
