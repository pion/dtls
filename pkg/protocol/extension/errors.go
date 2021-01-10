package extension

import "errors"

var (
	errBufferTooSmall       = errors.New("buffer is too small")
	errInvalidExtensionType = errors.New("invalid extension type")
	errInvalidSNIFormat     = errors.New("invalid server name format")
	errLengthMismatch       = errors.New("data length and declared length do not match")
)
