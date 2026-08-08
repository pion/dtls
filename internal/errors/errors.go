// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package errors centralizes internal DTLS error values.
package errors

import (
	"context"
	stderrors "errors"
)

var (
	ErrConnClosed = stderrors.New("conn is closed")

	ErrDeadlineExceeded   = context.DeadlineExceeded
	ErrInvalidContentType = stderrors.New("invalid content type")
	ErrBufferTooSmall     = stderrors.New("buffer is too small")
	ErrInvalidPacket      = stderrors.New("invalid packet")

	ErrContextUnsupported           = stderrors.New("context is not supported for ExportKeyingMaterial")
	ErrHandshakeInProgress          = stderrors.New("handshake is in progress")
	ErrReservedExportKeyingMaterial = stderrors.New("ExportKeyingMaterial can not be used with a reserved label")
	ErrApplicationDataEpochZero     = stderrors.New("ApplicationData with epoch of 0")
	ErrUnhandledContextType         = stderrors.New("unhandled contentType")

	ErrCertificateVerifyNoCertificate = stderrors.New(
		"client sent certificate verify but we have no certificate to verify",
	)
	ErrCipherSuiteNoIntersection    = stderrors.New("client+server do not support any shared cipher suites")
	ErrClientCertificateNotVerified = stderrors.New("client sent certificate but did not verify it")
	ErrClientCertificateRequired    = stderrors.New("server required client verification, but got none")
	ErrClientNoMatchingSRTPProfile  = stderrors.New("server responded with SRTP Profile we do not support")
	ErrClientRequiredButNoServerEMS = stderrors.New(
		"client required Extended Master Secret extension, but server does not support it",
	)
	ErrCookieMismatch                       = stderrors.New("client+server cookie does not match")
	ErrIdentityNoPSK                        = stderrors.New("PSK Identity Hint provided but PSK is nil")
	ErrInvalidCertificate                   = stderrors.New("no certificate provided")
	ErrCertificateVerificationFailed        = stderrors.New("certificate verification failed")
	ErrInvalidCipherSuite                   = stderrors.New("invalid or unknown cipher suite")
	ErrInvalidClientAuthType                = stderrors.New("invalid client auth type")
	ErrInvalidClientHello                   = stderrors.New("invalid ClientHello")
	ErrMissingClientHelloExtension          = stderrors.New("DTLS 1.3 ClientHello missing mandatory extension")
	ErrInvalidHelloRetryRequest             = stderrors.New("invalid HelloRetryRequest")
	ErrInvalidECDSASignature                = stderrors.New("ECDSA signature contained zero or negative values")
	ErrInvalidPrivateKey                    = stderrors.New("invalid private key type")
	ErrInvalidSignatureAlgorithm            = stderrors.New("invalid signature algorithm")
	ErrInvalidExtendedMasterSecretType      = stderrors.New("invalid extended master secret type")
	ErrInvalidCertificateSignatureAlgorithm = stderrors.New(
		"certificate uses a signature algorithm that is not allowed",
	)
	ErrKeySignatureMismatch    = stderrors.New("expected and actual key signature do not match")
	ErrInvalidCertificateOID   = stderrors.New("certificate OID does not match signature algorithm")
	ErrNilNextConn             = stderrors.New("conn can not be created with a nil nextConn")
	ErrNoAvailableCipherSuites = stderrors.New(
		"connection can not be created, no CipherSuites satisfy this Config",
	)
	ErrNoAvailablePSKCipherSuite = stderrors.New(
		"connection can not be created, pre-shared key present but no compatible CipherSuite",
	)
	ErrNoAvailableCertificateCipherSuite = stderrors.New(
		"connection can not be created, certificate present but no compatible CipherSuite",
	)
	ErrNoAvailableSignatureSchemes = stderrors.New(
		"connection can not be created, no SignatureScheme satisfy this Config",
	)
	ErrNoCertificates            = stderrors.New("no certificates configured")
	ErrNoConfigProvided          = stderrors.New("no config provided")
	ErrNoSupportedEllipticCurves = stderrors.New(
		"client requested zero or more elliptic curves that are not supported by the server",
	)
	ErrUnsupportedProtocolVersion        = stderrors.New("unsupported protocol version")
	ErrNoCommonProtocolVersion           = stderrors.New("no common DTLS version between peer and local")
	ErrInvalidProtocolVersionState       = stderrors.New("invalid protocol version in state")
	ErrInvalidServerHello                = stderrors.New("invalid ServerHello")
	ErrUnexpectedSecondHelloRetryRequest = stderrors.New("server sent a second HelloRetryRequest")
	ErrServerKeyShareMissing             = stderrors.New("ServerHello did not contain a key_share entry")
	ErrServerKeyShareUnknownGroup        = stderrors.New(
		"ServerHello key_share selected a group the client did not offer",
	)
	ErrPSKAndIdentityMustBeSetForClient = stderrors.New("PSK and PSK Identity Hint must both be set for client")
	ErrRequestedButNoSRTPExtension      = stderrors.New(
		"SRTP support was requested but server did not respond with use_srtp extension",
	)
	ErrServerNoMatchingSRTPProfile  = stderrors.New("client requested SRTP but we have no matching profiles")
	ErrServerRequiredButNoClientEMS = stderrors.New(
		"server requires the Extended Master Secret extension, but the client does not support it",
	)
	ErrVerifyDataMismatch            = stderrors.New("expected and actual verify data does not match")
	ErrNotAcceptableCertificateChain = stderrors.New("certificate chain is not signed by an acceptable CA")

	ErrInvalidFlight                         = stderrors.New("invalid flight number")
	ErrFlightUnimplemented13                 = stderrors.New("unimplemented DTLS 1.3 flight")
	ErrStateUnimplemented13                  = stderrors.New("unimplemented DTLS 1.3 handshake state")
	ErrHandshakeTranscriptMissingClientHello = stderrors.New(
		"DTLS 1.3 client transcript missing initial ClientHello",
	)
	ErrKeySignatureGenerateUnimplemented = stderrors.New("unable to generate key signature, unimplemented")
	ErrKeySignatureVerifyUnimplemented   = stderrors.New("unable to verify key signature, unimplemented")
	ErrLengthMismatch                    = stderrors.New("data length and declared length do not match")
	ErrSequenceNumberOverflow            = stderrors.New("sequence number overflow")
	ErrInvalidFSMTransition              = stderrors.New("invalid state machine transition")
	ErrFailedToAccessPoolReadBuffer      = stderrors.New("failed to access pool read buffer")
	ErrFragmentBufferOverflow            = stderrors.New("fragment buffer overflow")
	ErrCipherSuiteNotSet                 = stderrors.New("cipher suite not set")
	ErrHandshakeSequenceOverflow         = stderrors.New("handshake message sequence overflow")
	ErrUnexpectedPostHandshakeMessage    = stderrors.New("unexpected DTLS 1.3 post-handshake message")

	ErrEmptyCertificates = stderrors.New(
		"certificates option requires at least one certificate",
	)
	ErrEmptyCipherSuites = stderrors.New(
		"cipher suites option requires at least one cipher suite",
	)
	ErrNilCustomCipherSuites = stderrors.New(
		"custom cipher suites option requires a non-nil function",
	)
	ErrEmptySignatureSchemes = stderrors.New(
		"signature schemes option requires at least one scheme",
	)
	ErrEmptyCertificateSignatureSchemes = stderrors.New(
		"certificate signature schemes option requires at least one scheme",
	)
	ErrEmptySRTPProtectionProfiles = stderrors.New(
		"SRTP protection profiles option requires at least one profile",
	)
	ErrInvalidFlightInterval    = stderrors.New("flight interval must be positive")
	ErrNilPSKCallback           = stderrors.New("PSK option requires a non-nil callback")
	ErrNilVerifyPeerCertificate = stderrors.New(
		"verify peer certificate option requires a non-nil callback",
	)
	ErrNilVerifyConnection = stderrors.New(
		"verify connection option requires a non-nil callback",
	)
	ErrInvalidMTU                    = stderrors.New("MTU must be positive")
	ErrInvalidReplayProtectionWindow = stderrors.New(
		"replay protection window must be non-negative",
	)
	ErrEmptySupportedProtocols = stderrors.New(
		"supported protocols option requires at least one protocol",
	)
	ErrEmptyEllipticCurves = stderrors.New(
		"elliptic curves option requires at least one curve",
	)
	ErrUnsupportedEllipticCurveVersion = stderrors.New(
		"elliptic curve is not supported for the configured DTLS version",
	)
	ErrNilGetClientCertificate = stderrors.New(
		"get client certificate option requires a non-nil callback",
	)
	ErrNilConnectionIDGenerator = stderrors.New(
		"connection ID generator option requires a non-nil function",
	)
	ErrNilPaddingLengthGenerator = stderrors.New(
		"padding length generator option requires a non-nil function",
	)
	ErrNilHelloRandomBytesGenerator = stderrors.New(
		"hello random bytes generator option requires a non-nil function",
	)
	ErrNilClientHelloMessageHook = stderrors.New(
		"client hello message hook option requires a non-nil function",
	)
	ErrNilGetCertificate = stderrors.New(
		"get certificate option requires a non-nil callback",
	)
	ErrNilServerHelloMessageHook = stderrors.New(
		"server hello message hook option requires a non-nil function",
	)
	ErrNilCertificateRequestMessageHook = stderrors.New(
		"certificate request message hook option requires a non-nil function",
	)
	ErrNilOnConnectionAttempt = stderrors.New(
		"on connection attempt option requires a non-nil callback",
	)

	ErrInvalidHandshakeTranscriptMessage  = stderrors.New("invalid DTLS 1.3 handshake transcript message")
	ErrHandshakeTranscriptHashNotSelected = stderrors.New(
		"DTLS 1.3 handshake transcript hash is not selected",
	)
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

	ErrALPNInvalidFormat           = stderrors.New("invalid alpn format")
	ErrALPNNoAppProto              = stderrors.New("no application protocol")
	ErrInvalidExtensionType        = stderrors.New("invalid extension type")
	ErrInvalidSNIFormat            = stderrors.New("invalid server name format")
	ErrInvalidCIDFormat            = stderrors.New("invalid connection ID format")
	ErrMasterKeyIdentifierTooLarge = stderrors.New("master key identifier is over 255 bytes")
	ErrUseSRTPDataTooLarge         = stderrors.New("use_srtp extension data exceeds uint16 length")
	ErrPointFormatsTooLarge        = stderrors.New("point formats must not be longer than 255 ")
	ErrPreSharedKeyFormat          = stderrors.New("invalid Pre-Shared Key extension format")
	ErrPskKeyExchangeModesFormat   = stderrors.New(
		"invalid Pre-Shared Key Exchange Modes extension format",
	)
	ErrNoPskKeyExchangeMode = stderrors.New(
		"no mode set for the Pre-Shared Key Exchange Modes extension",
	)
	ErrCookieExtFormat                = stderrors.New("invalid cookie format")
	ErrInvalidKeyShareFormat          = stderrors.New("invalid key_share format")
	ErrDuplicateKeyShare              = stderrors.New("duplicate key_share group")
	ErrInvalidSupportedVersionsFormat = stderrors.New("invalid supported_versions format")
	ErrInvalidDTLSVersion             = stderrors.New("invalid dtls version was provided")
	ErrEarlyDataIndicationFormat      = stderrors.New("invalid Early Data Indication extension format")
	ErrInvalidCertificateAuthFormat   = stderrors.New(
		"invalid Certificate Authorities extension format",
	)
	ErrEmptyOIDFilter   = stderrors.New("no oid set for a OID filter")
	ErrOIDFiltersFormat = stderrors.New("invalid OID filters extension format")
	ErrDuplicateOID     = stderrors.New("duplicate OID filters")

	ErrUnableToMarshalFragmented = stderrors.New("unable to marshal fragmented handshakes")
	ErrHandshakeMessageUnset     = stderrors.New("handshake message unset, unable to marshal")
	ErrInvalidClientKeyExchange  = stderrors.New(
		"unable to determine if ClientKeyExchange is a public key or PSK Identity",
	)
	ErrInvalidSignHashAlgorithm  = stderrors.New("invalid signature/hash algorithm")
	ErrCookieTooLong             = stderrors.New("cookie must not be longer than 255 bytes")
	ErrSessionIDTooLong          = stderrors.New("session ID must not be longer than 255 bytes")
	ErrCertificateTypesTooLong   = stderrors.New("certificate types must not be longer than 255 entries")
	ErrCompressionMethodsTooLong = stderrors.New(
		"compression methods must not be longer than 255 entries",
	)
	ErrPublicKeyTooLong         = stderrors.New("public key must not be longer than 255 bytes")
	ErrInvalidEllipticCurveType = stderrors.New("invalid or unknown elliptic curve type")
	ErrInvalidNamedCurve        = stderrors.New("invalid named curve")
	ErrCipherSuiteUnset         = stderrors.New(
		"server hello can not be created without a cipher suite",
	)
	ErrCompressionMethodUnset = stderrors.New(
		"server hello can not be created without a compression method",
	)
	ErrInvalidCompressionMethod         = stderrors.New("invalid or unknown compression method")
	ErrNotImplemented                   = stderrors.New("feature has not been implemented yet")
	ErrInvalidCertificateRequestContext = stderrors.New("invalid certificate request context")
	ErrInvalidCertificateEntry          = stderrors.New("invalid certificate entry")
	ErrCertificateRequestContextTooLong = stderrors.New(
		"certificate request context must not be longer than 255 bytes",
	)
	ErrCertificateListTooLong = stderrors.New(
		"certificate list must not be longer than 2^24-1 bytes",
	)
	ErrInvalidExtensionsLength             = stderrors.New("extensions data must be between 2 and 2^16-1 bytes")
	ErrMissingSignatureAlgorithmsExtension = stderrors.New(
		"signature_algorithms extension is required in CertificateRequest",
	)
	ErrInvalidKeyUpdate         = stderrors.New("invalid KeyUpdate request")
	ErrInvalidConnectionIDUsage = stderrors.New("invalid connection ID usage")
	ErrTicketNonceTooLong       = stderrors.New("ticket nonce must not be longer than 255 bytes")
	ErrInvalidTicketLength      = stderrors.New("ticket must be between 1 and 65535 bytes")

	ErrInvalidPacketLength        = stderrors.New("packet length and declared length do not match")
	ErrInvalidCiphertextHeader    = stderrors.New("invalid dtls 1.3 ciphertext header")
	ErrInvalidEpoch               = stderrors.New("invalid epoch")
	ErrCIDTooBig                  = stderrors.New("connection ID size is too big")
	ErrInvalidUnifiedHeaderFormat = stderrors.New("invalid dtls 1.3 unified header format")

	ErrCipherSuiteNotInit                        = stderrors.New("CipherSuite has not been initialized")
	ErrCipherSuiteRecordProtectionNotImplemented = stderrors.New(
		"DTLS 1.3 cipher suite record protection is not implemented",
	)
	ErrNotEnoughRoomForNonce = stderrors.New("buffer not long enough to contain nonce")
	ErrDecryptPacket         = stderrors.New("failed to decrypt packet")
	ErrInvalidMAC            = stderrors.New("invalid mac")
	ErrFailedToCast          = stderrors.New("failed to cast")

	ErrCCMInvalidBlockSize   = stderrors.New("ccm: NewCCM requires 128-bit block cipher")
	ErrCCMInvalidTagSize     = stderrors.New("ccm: tagsize must be 4, 6, 8, 10, 12, 14, or 16")
	ErrCCMInvalidNonceSize   = stderrors.New("ccm: invalid nonce size")
	ErrCCMPlaintextTooLong   = stderrors.New("ccm: plaintext too large")
	ErrCCMOpen               = stderrors.New("ccm: message authentication failed")
	ErrCCMCiphertextTooShort = stderrors.New("ccm: ciphertext too short")
	ErrCCMCiphertextTooLong  = stderrors.New("ccm: ciphertext too long")

	ErrFingerprintHashUnavailable = stderrors.New(
		"fingerprint: hash algorithm is not linked into the binary",
	)
	ErrFingerprintInvalidLength        = stderrors.New("fingerprint: invalid fingerprint length")
	ErrFingerprintInvalidHashAlgorithm = stderrors.New("fingerprint: invalid hash algorithm")

	ErrKeyScheduleMissingHashFunction = stderrors.New(
		"HKDF-Extract expected a non-nil hash function",
	)
	ErrKeyScheduleLabelTooSmall = stderrors.New(
		"HKDF-Expand-Label expected a label with length >= 7",
	)
	ErrKeyScheduleLabelTooBig = stderrors.New(
		"HKDF-Expand-Label expected a label with length <= 255",
	)
	ErrKeyScheduleContextTooBig = stderrors.New(
		"HKDF-Expand-Label expected a context with length <= 255",
	)
	ErrKeyScheduleLengthTooBig = stderrors.New(
		"HKDF-Expand-Label expected a length <= 65535",
	)

	ErrSelfSignInvalidPrivateKey = stderrors.New("selfsign: invalid private key type")

	ErrInvalidHashAlgorithm      = stderrors.New("invalid hash algorithm")
	ErrNetBufferTimeout          = stderrors.New("buffer: i/o timeout")
	ErrUDPClosedListener         = stderrors.New("udp: listener closed")
	ErrUDPListenQueueExceeded    = stderrors.New("udp: listen queue exceeded")
	ErrUDPListenPacketNotUDPConn = stderrors.New(
		"listen packet not a *net.UDPConn",
	)
)
