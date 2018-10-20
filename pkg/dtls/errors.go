package dtls

import "errors"

var (
	errInvalidCipherSpec       = errors.New("dtls: cipher spec invalid")
	errDTLSPacketInvalidLength = errors.New("dtls: packet is too short")
	errInvalidContentType      = errors.New("dtls: invalid content type")
	errInvalidHandshakeType    = errors.New("dtls: invalid handshake type")
	errBufferTooSmall          = errors.New("dtls: buffer is too small")
	errSequenceNumberOverflow  = errors.New("dtls: sequence number overflow")
	errNotImplemented          = errors.New("dtls: feature has not been implemented yet")
	errLengthMismatch          = errors.New("dtls: data length and declared length do not match")
	errHandshakeMessageUnset   = errors.New("dtls: handshake message unset, unable to marshal")
)
