package dtls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/xerrors"
)

// Typed errors
var (
	ErrConnClosed = &ErrFatal{errors.New("conn is closed")}

	errDeadlineExceeded = &ErrTimeout{xerrors.Errorf("read/write timeout: %w", context.DeadlineExceeded)}

	errBufferTooSmall               = &ErrTemporary{errors.New("buffer is too small")}
	errContextUnsupported           = &ErrTemporary{errors.New("context is not supported for ExportKeyingMaterial")}
	errDTLSPacketInvalidLength      = &ErrTemporary{errors.New("packet is too short")}
	errHandshakeInProgress          = &ErrTemporary{errors.New("handshake is in progress")}
	errInvalidContentType           = &ErrTemporary{errors.New("invalid content type")}
	errInvalidMAC                   = &ErrTemporary{errors.New("invalid mac")}
	errInvalidPacketLength          = &ErrTemporary{errors.New("packet length and declared length do not match")}
	errReservedExportKeyingMaterial = &ErrTemporary{errors.New("ExportKeyingMaterial can not be used with a reserved label")}

	errCertificateVerifyNoCertificate   = &ErrFatal{errors.New("client sent certificate verify but we have no certificate to verify")}
	errCipherSuiteNoIntersection        = &ErrFatal{errors.New("client+server do not support any shared cipher suites")}
	errCipherSuiteUnset                 = &ErrFatal{errors.New("server hello can not be created without a cipher suite")}
	errClientCertificateNotVerified     = &ErrFatal{errors.New("client sent certificate but did not verify it")}
	errClientCertificateRequired        = &ErrFatal{errors.New("server required client verification, but got none")}
	errClientNoMatchingSRTPProfile      = &ErrFatal{errors.New("server responded with SRTP Profile we do not support")}
	errClientRequiredButNoServerEMS     = &ErrFatal{errors.New("client required Extended Master Secret extension, but server does not support it")}
	errCompressionMethodUnset           = &ErrFatal{errors.New("server hello can not be created without a compression method")}
	errCookieMismatch                   = &ErrFatal{errors.New("client+server cookie does not match")}
	errCookieTooLong                    = &ErrFatal{errors.New("cookie must not be longer then 255 bytes")}
	errHandshakeTimeout                 = &ErrFatal{xerrors.Errorf("the connection timed out during the handshake: %w", context.DeadlineExceeded)}
	errIdentityNoPSK                    = &ErrFatal{errors.New("PSK Identity Hint provided but PSK is nil")}
	errInvalidCertificate               = &ErrFatal{errors.New("no certificate provided")}
	errInvalidCipherSpec                = &ErrFatal{errors.New("cipher spec invalid")}
	errInvalidCipherSuite               = &ErrFatal{errors.New("invalid or unknown cipher suite")}
	errInvalidClientKeyExchange         = &ErrFatal{errors.New("unable to determine if ClientKeyExchange is a public key or PSK Identity")}
	errInvalidCompressionMethod         = &ErrFatal{errors.New("invalid or unknown compression method")}
	errInvalidECDSASignature            = &ErrFatal{errors.New("ECDSA signature contained zero or negative values")}
	errInvalidEllipticCurveType         = &ErrFatal{errors.New("invalid or unknown elliptic curve type")}
	errInvalidExtensionType             = &ErrFatal{errors.New("invalid extension type")}
	errInvalidHashAlgorithm             = &ErrFatal{errors.New("invalid hash algorithm")}
	errInvalidNamedCurve                = &ErrFatal{errors.New("invalid named curve")}
	errInvalidPrivateKey                = &ErrFatal{errors.New("invalid private key type")}
	errInvalidSNIFormat                 = &ErrFatal{errors.New("invalid server name format")}
	errInvalidSignatureAlgorithm        = &ErrFatal{errors.New("invalid signature algorithm")}
	errKeySignatureMismatch             = &ErrFatal{errors.New("expected and actual key signature do not match")}
	errNilNextConn                      = &ErrFatal{errors.New("Conn can not be created with a nil nextConn")}
	errNoAvailableCipherSuites          = &ErrFatal{errors.New("connection can not be created, no CipherSuites satisfy this Config")}
	errNoCertificates                   = &ErrFatal{errors.New("no certificates configured")}
	errNoConfigProvided                 = &ErrFatal{errors.New("no config provided")}
	errNoSupportedEllipticCurves        = &ErrFatal{errors.New("client requested zero or more elliptic curves that are not supported by the server")}
	errPSKAndCertificate                = &ErrFatal{errors.New("Certificate and PSK provided")} // nolint:stylecheck
	errPSKAndIdentityMustBeSetForClient = &ErrFatal{errors.New("PSK and PSK Identity Hint must both be set for client")}
	errRequestedButNoSRTPExtension      = &ErrFatal{errors.New("SRTP support was requested but server did not respond with use_srtp extension")}
	errServerMustHaveCertificate        = &ErrFatal{errors.New("Certificate is mandatory for server")} // nolint:stylecheck
	errServerNoMatchingSRTPProfile      = &ErrFatal{errors.New("client requested SRTP but we have no matching profiles")}
	errServerRequiredButNoClientEMS     = &ErrFatal{errors.New("server requires the Extended Master Secret extension, but the client does not support it")}
	errVerifyDataMismatch               = &ErrFatal{errors.New("expected and actual verify data does not match")}

	errHandshakeMessageUnset             = &ErrInternal{errors.New("handshake message unset, unable to marshal")}
	errInvalidFlight                     = &ErrInternal{errors.New("invalid flight number")}
	errKeySignatureGenerateUnimplemented = &ErrInternal{errors.New("unable to generate key signature, unimplemented")}
	errKeySignatureVerifyUnimplemented   = &ErrInternal{errors.New("unable to verify key signature, unimplemented")}
	errLengthMismatch                    = &ErrInternal{errors.New("data length and declared length do not match")}
	errNotEnoughRoomForNonce             = &ErrInternal{errors.New("buffer not long enough to contain nonce")}
	errNotImplemented                    = &ErrInternal{errors.New("feature has not been implemented yet")}
	errSequenceNumberOverflow            = &ErrInternal{errors.New("sequence number overflow")}
	errUnableToMarshalFragmented         = &ErrInternal{errors.New("unable to marshal fragmented handshakes")}
)

// ErrFatal indicates that the DTLS connection is no longer available.
// It is mainly caused by wrong configuration of server or client.
type ErrFatal struct {
	Err error
}

// ErrInternal indicates and internal error caused by the implementation, and the DTLS connection is no longer available.
// It is mainly caused by bugs or tried to use unimplemented features.
type ErrInternal struct {
	Err error
}

// ErrTemporary indicates that the DTLS connection is still available, but the request was failed temporary.
type ErrTemporary struct {
	Err error
}

// ErrTimeout indicates that the request was timed out.
type ErrTimeout struct {
	Err error
}

// Timeout implements net.Error.Timeout()
func (*ErrFatal) Timeout() bool { return false }

// Temporary implements net.Error.Temporary()
func (*ErrFatal) Temporary() bool { return false }

// Unwrap implements Go1.13 error unwrapper.
func (e *ErrFatal) Unwrap() error { return e.Err }

func (e *ErrFatal) Error() string { return fmt.Sprintf("dtls fatal: %v", e.Err) }

// Timeout implements net.Error.Timeout()
func (*ErrInternal) Timeout() bool { return false }

// Temporary implements net.Error.Temporary()
func (*ErrInternal) Temporary() bool { return false }

// Unwrap implements Go1.13 error unwrapper.
func (e *ErrInternal) Unwrap() error { return e.Err }

func (e *ErrInternal) Error() string { return fmt.Sprintf("dtls internal: %v", e.Err) }

// Timeout implements net.Error.Timeout()
func (*ErrTemporary) Timeout() bool { return false }

// Temporary implements net.Error.Temporary()
func (*ErrTemporary) Temporary() bool { return true }

// Unwrap implements Go1.13 error unwrapper.
func (e *ErrTemporary) Unwrap() error { return e.Err }

func (e *ErrTemporary) Error() string { return fmt.Sprintf("dtls temporary: %v", e.Err) }

// Timeout implements net.Error.Timeout()
func (*ErrTimeout) Timeout() bool { return true }

// Temporary implements net.Error.Temporary()
func (*ErrTimeout) Temporary() bool { return true }

// Unwrap implements Go1.13 error unwrapper.
func (e *ErrTimeout) Unwrap() error { return e.Err }

func (e *ErrTimeout) Error() string { return fmt.Sprintf("dtls timeout: %v", e.Err) }

// errAlert wraps DTLS alert notification as an error
type errAlert struct {
	*alert
}

func (e *errAlert) Error() string {
	return fmt.Sprintf("alert: %s", e.alert.String())
}

func (e *errAlert) IsFatalOrCloseNotify() bool {
	return e.alertLevel == alertLevelFatal || e.alertDescription == alertCloseNotify
}

// netError translates an error from underlying Conn to corresponding net.Error.
func netError(err error) error {
	switch err {
	case io.EOF, context.Canceled, context.DeadlineExceeded:
		// Return io.EOF and context errors as is.
		return err
	}
	switch e := err.(type) {
	case (*net.OpError):
		if se, ok := e.Err.(*os.SyscallError); ok {
			if se.Timeout() {
				return &ErrTimeout{err}
			}
			if isOpErrorTemporary(se) {
				return &ErrTemporary{err}
			}
		}
	case (net.Error):
		return err
	}
	return &ErrFatal{err}
}
