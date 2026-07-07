// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package errors centralizes internal DTLS error values.
package errors

import (
	"context"
	stderrors "errors"
)

var ( //nolint:gochecknoglobals,lll
	errBufferTooSmall              = stderrors.New("buffer is too small")
	errLengthMismatch              = stderrors.New("data length and declared length do not match")
	errInvalidContentType          = stderrors.New("invalid content type")
	errUnsupportedProtocolVersion  = stderrors.New("unsupported protocol version")
	errSequenceNumberOverflow      = stderrors.New("sequence number overflow")
	errInvalidPrivateKey           = stderrors.New("invalid private key type")
	errInvalidSignatureAlgorithm   = stderrors.New("invalid signature algorithm")
	errNoAvailableSignatureSchemes = stderrors.New("connection can not be created, no SignatureScheme satisfy this Config") //nolint:lll
	errInvalidNamedCurve           = stderrors.New("invalid named curve")
	errNoAvailableCipherSuites     = stderrors.New(
		"connection can not be created, no CipherSuites satisfy this Config",
	)
	errNoAvailablePSKCipherSuite      = stderrors.New("connection can not be created, pre-shared key present but no compatible CipherSuite") //nolint:lll
	errNoAvailableCertificateSuite    = stderrors.New("connection can not be created, certificate present but no compatible CipherSuite")    //nolint:lll
	errInvalidCertificate             = stderrors.New("no certificate provided")
	errInvalidCertificateOID          = stderrors.New("certificate OID does not match signature algorithm")
	errInvalidCertificateSignatureAlg = stderrors.New("certificate uses a signature algorithm that is not allowed")

	ErrConnClosed = stderrors.New("conn is closed")

	ErrDeadlineExceeded   = context.DeadlineExceeded //nolint:lll
	ErrInvalidContentType = errInvalidContentType    //nolint:lll
	ErrBufferTooSmall     = errBufferTooSmall        //nolint:lll
	ErrInvalidPacket      = stderrors.New("invalid packet")

	ErrContextUnsupported           = stderrors.New("context is not supported for ExportKeyingMaterial")
	ErrHandshakeInProgress          = stderrors.New("handshake is in progress") //nolint:lll
	ErrReservedExportKeyingMaterial = stderrors.New("ExportKeyingMaterial can not be used with a reserved label")
	ErrApplicationDataEpochZero     = stderrors.New("ApplicationData with epoch of 0") //nolint:lll
	ErrUnhandledContextType         = stderrors.New("unhandled contentType")           //nolint:lll

	ErrCertificateVerifyNoCertificate = stderrors.New(
		"client sent certificate verify but we have no certificate to verify",
	)
	ErrCipherSuiteNoIntersection    = stderrors.New("client+server do not support any shared cipher suites") //nolint:lll
	ErrClientCertificateNotVerified = stderrors.New("client sent certificate but did not verify it")         //nolint:lll
	ErrClientCertificateRequired    = stderrors.New("server required client verification, but got none")     //nolint:lll
	ErrClientNoMatchingSRTPProfile  = stderrors.New("server responded with SRTP Profile we do not support")  //nolint:lll
	ErrClientRequiredButNoServerEMS = stderrors.New(
		"client required Extended Master Secret extension, but server does not support it",
	)
	ErrCookieMismatch                       = stderrors.New("client+server cookie does not match")       //nolint:lll
	ErrIdentityNoPSK                        = stderrors.New("PSK Identity Hint provided but PSK is nil") //nolint:lll
	ErrInvalidCertificate                   = errInvalidCertificate                                      //nolint:lll
	ErrInvalidCipherSuite                   = stderrors.New("invalid or unknown cipher suite")           //nolint:lll
	ErrInvalidClientAuthType                = stderrors.New("invalid client auth type")
	ErrInvalidClientHello                   = stderrors.New("invalid ClientHello") //nolint:lll
	ErrMissingClientHelloExtension          = stderrors.New("DTLS 1.3 ClientHello missing mandatory extension")
	ErrInvalidHelloRetryRequest             = stderrors.New("invalid HelloRetryRequest")                         //nolint:lll
	ErrInvalidECDSASignature                = stderrors.New("ECDSA signature contained zero or negative values") //nolint:lll
	ErrInvalidPrivateKey                    = errInvalidPrivateKey                                               //nolint:lll
	ErrInvalidSignatureAlgorithm            = errInvalidSignatureAlgorithm
	ErrInvalidExtendedMasterSecretType      = stderrors.New("invalid extended master secret type") //nolint:lll
	ErrInvalidCertificateSignatureAlgorithm = errInvalidCertificateSignatureAlg
	ErrKeySignatureMismatch                 = stderrors.New("expected and actual key signature do not match") //nolint:lll
	ErrInvalidCertificateOID                = errInvalidCertificateOID
	ErrNilNextConn                          = stderrors.New("Conn can not be created with a nil nextConn") //nolint:lll,staticcheck
	ErrNoAvailableCipherSuites              = errNoAvailableCipherSuites
	ErrNoAvailablePSKCipherSuite            = errNoAvailablePSKCipherSuite
	ErrNoAvailableCertificateCipherSuite    = errNoAvailableCertificateSuite
	ErrNoAvailableSignatureSchemes          = errNoAvailableSignatureSchemes
	ErrNoCertificates                       = stderrors.New("no certificates configured") //nolint:lll
	ErrNoConfigProvided                     = stderrors.New("no config provided")
	ErrNoSupportedEllipticCurves            = stderrors.New(
		"client requested zero or more elliptic curves that are not supported by the server",
	)
	ErrUnsupportedProtocolVersion        = errUnsupportedProtocolVersion                                  //nolint:lll
	ErrNoCommonProtocolVersion           = stderrors.New("no common DTLS version between peer and local") //nolint:lll
	ErrInvalidProtocolVersionState       = stderrors.New("invalid protocol version in state")
	ErrInvalidServerHello                = stderrors.New("invalid ServerHello") //nolint:lll
	ErrUnexpectedSecondHelloRetryRequest = stderrors.New("server sent a second HelloRetryRequest")
	ErrServerKeyShareMissing             = stderrors.New("ServerHello did not contain a key_share entry") //nolint:lll
	ErrServerKeyShareUnknownGroup        = stderrors.New(
		"ServerHello key_share selected a group the client did not offer",
	)
	ErrPSKAndIdentityMustBeSetForClient = stderrors.New("PSK and PSK Identity Hint must both be set for client")
	ErrRequestedButNoSRTPExtension      = stderrors.New(
		"SRTP support was requested but server did not respond with use_srtp extension",
	)
	ErrServerNoMatchingSRTPProfile  = stderrors.New("client requested SRTP but we have no matching profiles") //nolint:lll
	ErrServerRequiredButNoClientEMS = stderrors.New(
		"server requires the Extended Master Secret extension, but the client does not support it",
	)
	ErrVerifyDataMismatch            = stderrors.New("expected and actual verify data does not match")      //nolint:lll
	ErrNotAcceptableCertificateChain = stderrors.New("certificate chain is not signed by an acceptable CA") //nolint:lll

	ErrInvalidFlight                         = stderrors.New("invalid flight number")                  //nolint:lll
	ErrFlightUnimplemented13                 = stderrors.New("unimplemented DTLS 1.3 flight")          //nolint:lll
	ErrStateUnimplemented13                  = stderrors.New("unimplemented DTLS 1.3 handshake state") //nolint:lll
	ErrHandshakeTranscriptMissingClientHello = stderrors.New("DTLS 1.3 client transcript missing initial ClientHello")
	ErrKeySignatureGenerateUnimplemented     = stderrors.New("unable to generate key signature, unimplemented")
	ErrKeySignatureVerifyUnimplemented       = stderrors.New("unable to verify key signature, unimplemented") //nolint:lll
	ErrLengthMismatch                        = errLengthMismatch                                              //nolint:lll
	ErrSequenceNumberOverflow                = errSequenceNumberOverflow                                      //nolint:lll
	ErrInvalidFSMTransition                  = stderrors.New("invalid state machine transition")              //nolint:lll
	ErrFailedToAccessPoolReadBuffer          = stderrors.New("failed to access pool read buffer")             //nolint:lll
	ErrFragmentBufferOverflow                = stderrors.New("fragment buffer overflow")
	ErrCipherSuiteNotSet                     = stderrors.New("cipher suite not set") //nolint:lll

	ErrEmptyCertificates                = stderrors.New("certificates option requires at least one certificate")   //nolint:lll
	ErrEmptyCipherSuites                = stderrors.New("cipher suites option requires at least one cipher suite") //nolint:lll
	ErrNilCustomCipherSuites            = stderrors.New("custom cipher suites option requires a non-nil function") //nolint:lll
	ErrEmptySignatureSchemes            = stderrors.New("signature schemes option requires at least one scheme")   //nolint:lll
	ErrEmptyCertificateSignatureSchemes = stderrors.New(
		"certificate signature schemes option requires at least one scheme",
	)
	ErrEmptySRTPProtectionProfiles      = stderrors.New("SRTP protection profiles option requires at least one profile")
	ErrInvalidFlightInterval            = stderrors.New("flight interval must be positive")       //nolint:lll
	ErrNilPSKCallback                   = stderrors.New("PSK option requires a non-nil callback") //nolint:lll
	ErrNilVerifyPeerCertificate         = stderrors.New("verify peer certificate option requires a non-nil callback")
	ErrNilVerifyConnection              = stderrors.New("verify connection option requires a non-nil callback")      //nolint:lll
	ErrInvalidMTU                       = stderrors.New("MTU must be positive")                                      //nolint:lll
	ErrInvalidReplayProtectionWindow    = stderrors.New("replay protection window must be non-negative")             //nolint:lll
	ErrEmptySupportedProtocols          = stderrors.New("supported protocols option requires at least one protocol") //nolint:lll
	ErrEmptyEllipticCurves              = stderrors.New("elliptic curves option requires at least one curve")        //nolint:lll
	ErrUnsupportedEllipticCurveVersion  = stderrors.New("elliptic curve is not supported for the configured DTLS version")
	ErrNilGetClientCertificate          = stderrors.New("get client certificate option requires a non-nil callback")
	ErrNilConnectionIDGenerator         = stderrors.New("connection ID generator option requires a non-nil function")
	ErrNilPaddingLengthGenerator        = stderrors.New("padding length generator option requires a non-nil function")
	ErrNilHelloRandomBytesGenerator     = stderrors.New("hello random bytes generator option requires a non-nil function")
	ErrNilClientHelloMessageHook        = stderrors.New("client hello message hook option requires a non-nil function")
	ErrNilGetCertificate                = stderrors.New("get certificate option requires a non-nil callback") //nolint:lll
	ErrNilServerHelloMessageHook        = stderrors.New("server hello message hook option requires a non-nil function")
	ErrNilCertificateRequestMessageHook = stderrors.New(
		"certificate request message hook option requires a non-nil function",
	)
	ErrNilOnConnectionAttempt = stderrors.New("on connection attempt option requires a non-nil callback") //nolint:lll

	ErrInvalidHandshakeTranscriptMessage      = stderrors.New("invalid DTLS 1.3 handshake transcript message")
	ErrHandshakeTranscriptHashNotSelected     = stderrors.New("DTLS 1.3 handshake transcript hash is not selected")
	ErrHandshakeTranscriptHashAlreadySelected = stderrors.New(
		"DTLS 1.3 handshake transcript hash is already selected",
	)
	ErrHandshakeTranscriptMessageChanged = stderrors.New(
		"DTLS 1.3 handshake transcript message changed during retransmission",
	)
	ErrHandshakeTranscriptExplicitAuthenticationRequired = stderrors.New(
		"DTLS 1.3 handshake transcript message requires explicit authentication before commit",
	)
	ErrHandshakeTranscriptHelloRetryRequestInvalid = stderrors.New(
		"invalid DTLS 1.3 HelloRetryRequest transcript transition",
	)

	ErrInvalidCipherSpec = stderrors.New("cipher spec invalid")
	ErrInvalidACK        = stderrors.New("ack invalid")

	ErrALPNInvalidFormat              = stderrors.New("invalid alpn format")     //nolint:lll
	ErrALPNNoAppProto                 = stderrors.New("no application protocol") //nolint:lll
	ErrInvalidExtensionType           = stderrors.New("invalid extension type")
	ErrInvalidSNIFormat               = stderrors.New("invalid server name format")   //nolint:lll
	ErrInvalidCIDFormat               = stderrors.New("invalid connection ID format") //nolint:lll
	ErrMasterKeyIdentifierTooLarge    = stderrors.New("master key identifier is over 255 bytes")
	ErrUseSRTPDataTooLarge            = stderrors.New("use_srtp extension data exceeds uint16 length") //nolint:lll
	ErrPointFormatsTooLarge           = stderrors.New("point formats must not be longer than 255 ")
	ErrPreSharedKeyFormat             = stderrors.New("invalid Pre-Shared Key extension format")                     //nolint:lll
	ErrPskKeyExchangeModesFormat      = stderrors.New("invalid Pre-Shared Key Exchange Modes extension format")      //nolint:lll
	ErrNoPskKeyExchangeMode           = stderrors.New("no mode set for the Pre-Shared Key Exchange Modes extension") //nolint:lll
	ErrCookieExtFormat                = stderrors.New("invalid cookie format")                                       //nolint:lll
	ErrInvalidKeyShareFormat          = stderrors.New("invalid key_share format")                                    //nolint:lll
	ErrDuplicateKeyShare              = stderrors.New("duplicate key_share group")                                   //nolint:lll
	ErrInvalidSupportedVersionsFormat = stderrors.New("invalid supported_versions format")
	ErrInvalidDTLSVersion             = stderrors.New("invalid dtls version was provided")                //nolint:lll
	ErrEarlyDataIndicationFormat      = stderrors.New("invalid Early Data Indication extension format")   //nolint:lll
	ErrInvalidCertificateAuthFormat   = stderrors.New("invalid Certificate Authorities extension format") //nolint:lll
	ErrEmptyOIDFilter                 = stderrors.New("no oid set for a OID filter")                      //nolint:lll
	ErrOIDFiltersFormat               = stderrors.New("invalid OID filters extension format")             //nolint:lll
	ErrDuplicateOID                   = stderrors.New("duplicate OID filters")                            //nolint:lll

	ErrUnableToMarshalFragmented = stderrors.New("unable to marshal fragmented handshakes")    //nolint:lll
	ErrHandshakeMessageUnset     = stderrors.New("handshake message unset, unable to marshal") //nolint:lll
	ErrInvalidClientKeyExchange  = stderrors.New(
		"unable to determine if ClientKeyExchange is a public key or PSK Identity",
	)
	ErrInvalidSignHashAlgorithm            = stderrors.New("invalid signature/hash algorithm")                      //nolint:lll
	ErrCookieTooLong                       = stderrors.New("cookie must not be longer than 255 bytes")              //nolint:lll
	ErrSessionIDTooLong                    = stderrors.New("session ID must not be longer than 255 bytes")          //nolint:lll
	ErrCertificateTypesTooLong             = stderrors.New("certificate types must not be longer than 255 entries") //nolint:lll
	ErrCompressionMethodsTooLong           = stderrors.New("compression methods must not be longer than 255 entries")
	ErrPublicKeyTooLong                    = stderrors.New("public key must not be longer than 255 bytes")                 //nolint:lll
	ErrInvalidEllipticCurveType            = stderrors.New("invalid or unknown elliptic curve type")                       //nolint:lll
	ErrInvalidNamedCurveFatal              = errInvalidNamedCurve                                                          //nolint:lll
	ErrCipherSuiteUnset                    = stderrors.New("server hello can not be created without a cipher suite")       //nolint:lll
	ErrCompressionMethodUnset              = stderrors.New("server hello can not be created without a compression method") //nolint:lll
	ErrInvalidCompressionMethod            = stderrors.New("invalid or unknown compression method")
	ErrNotImplemented                      = stderrors.New("feature has not been implemented yet") //nolint:lll
	ErrInvalidCertificateRequestContext    = stderrors.New("invalid certificate request context")
	ErrInvalidCertificateEntry             = stderrors.New("invalid certificate entry") //nolint:lll
	ErrCertificateRequestContextTooLong    = stderrors.New("certificate request context must not be longer than 255 bytes")
	ErrCertificateListTooLong              = stderrors.New("certificate list must not be longer than 2^24-1 bytes") //nolint:lll
	ErrInvalidExtensionsLength             = stderrors.New("extensions data must be between 2 and 2^16-1 bytes")
	ErrMissingSignatureAlgorithmsExtension = stderrors.New(
		"signature_algorithms extension is required in CertificateRequest",
	)

	ErrInvalidPacketLength        = stderrors.New("packet length and declared length do not match") //nolint:lll
	ErrInvalidCiphertextHeader    = stderrors.New("invalid dtls 1.3 ciphertext header")             //nolint:lll
	ErrInvalidEpoch               = stderrors.New("invalid epoch")                                  //nolint:lll
	ErrCIDTooBig                  = stderrors.New("connection ID size is too big")                  //nolint:lll
	ErrInvalidUnifiedHeaderFormat = stderrors.New("invalid dtls 1.3 unified header format")

	ErrCipherSuiteNotInit                        = stderrors.New("CipherSuite has not been initialized")
	ErrCipherSuiteRecordProtectionNotImplemented = stderrors.New(
		"DTLS 1.3 cipher suite record protection is not implemented",
	)
	ErrNotEnoughRoomForNonce = stderrors.New("buffer not long enough to contain nonce") //nolint:lll
	ErrDecryptPacket         = stderrors.New("failed to decrypt packet")                //nolint:lll
	ErrInvalidMAC            = stderrors.New("invalid mac")                             //nolint:lll
	ErrFailedToCast          = stderrors.New("failed to cast")                          //nolint:lll

	ErrCCMInvalidBlockSize   = stderrors.New("ccm: NewCCM requires 128-bit block cipher")       //nolint:lll
	ErrCCMInvalidTagSize     = stderrors.New("ccm: tagsize must be 4, 6, 8, 10, 12, 14, or 16") //nolint:lll
	ErrCCMInvalidNonceSize   = stderrors.New("ccm: invalid nonce size")                         //nolint:lll
	ErrCCMPlaintextTooLong   = stderrors.New("ccm: plaintext too large")                        //nolint:lll
	ErrCCMOpen               = stderrors.New("ccm: message authentication failed")              //nolint:lll
	ErrCCMCiphertextTooShort = stderrors.New("ccm: ciphertext too short")                       //nolint:lll
	ErrCCMCiphertextTooLong  = stderrors.New("ccm: ciphertext too long")                        //nolint:lll

	ErrFingerprintHashUnavailable      = stderrors.New("fingerprint: hash algorithm is not linked into the binary") //nolint:lll
	ErrFingerprintInvalidLength        = stderrors.New("fingerprint: invalid fingerprint length")                   //nolint:lll
	ErrFingerprintInvalidHashAlgorithm = stderrors.New(                                                             //nolint:lll
		"fingerprint: invalid hash algorithm",
	)

	ErrKeyScheduleMissingHashFunction = stderrors.New("HKDF-Extract expected a non-nil hash function")           //nolint:lll
	ErrKeyScheduleLabelTooSmall       = stderrors.New("HKDF-Expand-Label expected a label with length >= 7")     //nolint:lll
	ErrKeyScheduleLabelTooBig         = stderrors.New("HKDF-Expand-Label expected a label with length <= 255")   //nolint:lll
	ErrKeyScheduleContextTooBig       = stderrors.New("HKDF-Expand-Label expected a context with length <= 255") //nolint:lll
	ErrKeyScheduleLengthTooBig        = stderrors.New("HKDF-Expand-Label expected a length <= 65535")            //nolint:lll

	ErrInvalidNamedCurve         = errInvalidNamedCurve
	ErrSelfSignInvalidPrivateKey = stderrors.New("selfsign: invalid private key type") //nolint:lll

	ErrSignatureHashNoAvailableSignatureSchemes = errNoAvailableSignatureSchemes
	ErrSignatureHashInvalidSignatureAlgorithm   = errInvalidSignatureAlgorithm
	ErrSignatureHashInvalidHashAlgorithm        = stderrors.New("invalid hash algorithm") //nolint:lll
	ErrSignatureHashInvalidPrivateKey           = errInvalidPrivateKey
	ErrNetBufferTimeout                         = stderrors.New("buffer: i/o timeout")
	ErrUDPClosedListener                        = stderrors.New("udp: listener closed")
	ErrUDPListenQueueExceeded                   = stderrors.New("udp: listen queue exceeded")
	ErrUDPListenPacketNotUDPConn                = stderrors.New(
		"listen packet not a *net.UDPConn",
	)
)
