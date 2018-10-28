package dtls

import "errors"

var (
	errBufferTooSmall           = errors.New("dtls: buffer is too small")
	errCookieTooLong            = errors.New("dtls: cookie must not be longer then 255 bytes")
	errDTLSPacketInvalidLength  = errors.New("dtls: packet is too short")
	errHandshakeMessageUnset    = errors.New("dtls: handshake message unset, unable to marshal")
	errInvalidCipherSpec        = errors.New("dtls: cipher spec invalid")
	errInvalidCipherSuite       = errors.New("dtls: invalid or unknown cipher suite")
	errInvalidCompressionMethod = errors.New("dtls: invalid or unknown compression method")
	errInvalidContentType       = errors.New("dtls: invalid content type")
	errInvalidHandshakeType     = errors.New("dtls: invalid handshake type")
	errInvalidExtensionType     = errors.New("dtls: invalid extension type")
	errLengthMismatch           = errors.New("dtls: data length and declared length do not match")
	errNotImplemented           = errors.New("dtls: feature has not been implemented yet")
	errSequenceNumberOverflow   = errors.New("dtls: sequence number overflow")
	errCipherSuiteUnset         = errors.New("dtls: server hello can not be created without a cipher suite")
	errCompressionmethodUnset   = errors.New("dtls: server hello can not be created without a compression method")
)
