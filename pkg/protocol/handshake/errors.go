package handshake

import "errors"

// Typed errors
var (
	errUnableToMarshalFragmented = errors.New("unable to marshal fragmented handshakes")
	errHandshakeMessageUnset     = errors.New("handshake message unset, unable to marshal")
	errBufferTooSmall            = errors.New("buffer is too small")
	errLengthMismatch            = errors.New("data length and declared length do not match")
	errInvalidClientKeyExchange  = errors.New("unable to determine if ClientKeyExchange is a public key or PSK Identity")
	errInvalidHashAlgorithm      = errors.New("invalid hash algorithm")
	errInvalidSignatureAlgorithm = errors.New("invalid signature algorithm")
	errCookieTooLong             = errors.New("cookie must not be longer then 255 bytes")
	errInvalidEllipticCurveType  = errors.New("invalid or unknown elliptic curve type")
	errInvalidNamedCurve         = errors.New("invalid named curve")
	errCipherSuiteUnset          = errors.New("server hello can not be created without a cipher suite")
	errCompressionMethodUnset    = errors.New("server hello can not be created without a compression method")
	errInvalidCompressionMethod  = errors.New("invalid or unknown compression method")
	errNotImplemented            = errors.New("feature has not been implemented yet")
)
