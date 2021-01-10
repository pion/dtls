// Package recordlayer implements the TLS Record Layer https://tools.ietf.org/html/rfc5246#section-6
package recordlayer

import "errors"

var (
	errBufferTooSmall             = errors.New("buffer is too small")
	errInvalidPacketLength        = errors.New("packet length and declared length do not match")
	errSequenceNumberOverflow     = errors.New("sequence number overflow")
	errUnsupportedProtocolVersion = errors.New("unsupported protocol version")
	errInvalidContentType         = errors.New("invalid content type")
)
