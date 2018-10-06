package dtls

import "errors"

var (
	errInvalidCipherSpec       = errors.New("dtls: cipher spec invalid")
	errDTLSPacketInvalidLength = errors.New("dtls: packet is too short")
	errInvalidContentType      = errors.New("dtls: invalid content type")
	errBufferTooSmall          = errors.New("dtls: buffer is too small")
	errNotImplemented          = errors.New("dtls: feature has not been implemented yet")
)
