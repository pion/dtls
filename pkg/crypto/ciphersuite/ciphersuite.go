// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ciphersuite defines cipher-suite descriptors, immutable record
// metadata, protection capabilities, and DTLS record-protection contracts.
package ciphersuite

import (
	"errors"
	"hash"
	"math"

	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/protocol"
)

var (
	// ErrInvalidCapabilities reports a malformed cipher suite capabilities.
	ErrInvalidCapabilities = errors.New("invalid cipher suite capabilities")
	// ErrAuthenticationFailed reports that a protected record could not be
	// authenticated.
	ErrAuthenticationFailed = errors.New("record authentication failed")
)

// AuthenticationType controls the authentication method used by a cipher suite.
type AuthenticationType uint8

// AuthenticationType values.
const (
	AuthenticationTypeCertificate AuthenticationType = iota + 1
	AuthenticationTypePreSharedKey
	AuthenticationTypeAnonymous
)

// KeyExchangeAlgorithm identifies cipher-suite key exchange requirements.
type KeyExchangeAlgorithm uint8

// KeyExchangeAlgorithm values form a bitmask.
const (
	KeyExchangeAlgorithmNone KeyExchangeAlgorithm = 0
	KeyExchangeAlgorithmPsk  KeyExchangeAlgorithm = 1 << iota
	KeyExchangeAlgorithmEcdhe
)

// Has reports whether all bits in v are set.
func (a KeyExchangeAlgorithm) Has(v KeyExchangeAlgorithm) bool {
	return a&v == v
}

// Suite describes a cipher suite without connection-specific key material.
type Suite interface {
	String() string
	ID() ID
	CertificateType() clientcertificate.Type
	HashFunc() func() hash.Hash
	AuthenticationType() AuthenticationType
	KeyExchangeAlgorithm() KeyExchangeAlgorithm
	ECC() bool
	Capabilities() Capabilities
}

type lengthMode uint8

const (
	lengthModeAEAD lengthMode = iota + 1
	lengthModeCBC
)

// Capabilities is protection metadata for one protocol
// version.
type Capabilities struct {
	version          protocol.Version
	mode             lengthMode
	maxPlaintextLen  int
	maxProtectedLen  int
	explicitNonceLen int
	tagLen           int
	macLen           int
	blockLen         int
	maskSampleLen    int
}

// NewAEADCapabilities constructs capabilities for an AEAD suite.
func NewAEADCapabilities(
	version protocol.Version,
	maxPlaintextLen, explicitNonceLen, tagLen, maskSampleLen int,
) (Capabilities, error) {
	maxProtectedLen, valid := validAEADLengths(maxPlaintextLen, explicitNonceLen, tagLen)
	if !valid || !validAEADMask(version, maskSampleLen, maxProtectedLen) {
		return Capabilities{}, ErrInvalidCapabilities
	}

	return Capabilities{
		version:          version,
		mode:             lengthModeAEAD,
		maxPlaintextLen:  maxPlaintextLen,
		maxProtectedLen:  maxProtectedLen,
		explicitNonceLen: explicitNonceLen,
		tagLen:           tagLen,
		maskSampleLen:    maskSampleLen,
	}, nil
}

func validAEADLengths(maxPlaintextLen, explicitNonceLen, tagLen int) (int, bool) {
	if !validPositiveUint16(maxPlaintextLen) || !validNonNegativeUint16(explicitNonceLen) ||
		!validPositiveUint16(tagLen) {
		return 0, false
	}

	maxProtectedLen := maxPlaintextLen + explicitNonceLen + tagLen

	return maxProtectedLen, maxProtectedLen <= math.MaxUint16
}

func validPositiveUint16(value int) bool {
	return value > 0 && value <= math.MaxUint16
}

func validNonNegativeUint16(value int) bool {
	return value >= 0 && value <= math.MaxUint16
}

func validAEADMask(version protocol.Version, maskSampleLen, maxProtectedLen int) bool {
	switch version {
	case protocol.Version1_2:
		return maskSampleLen == 0
	case protocol.Version1_3:
		return maskSampleLen > 0 && maskSampleLen <= maxProtectedLen
	default:
		return false
	}
}

// NewCBCCapabilities constructs capabilities for a MAC-then-encrypt CBC suite.
func NewCBCCapabilities(maxPlaintextLen, macLen, blockLen int) (Capabilities, error) {
	if maxPlaintextLen <= 0 || maxPlaintextLen > math.MaxUint16 ||
		blockLen <= 0 || blockLen > 256 || macLen <= 0 || macLen > math.MaxUint16 {
		return Capabilities{}, ErrInvalidCapabilities
	}
	maxProtectedLen := blockLen + ((maxPlaintextLen+macLen+256)/blockLen)*blockLen
	if maxProtectedLen <= 0 || maxProtectedLen > math.MaxUint16 || macLen > maxProtectedLen {
		return Capabilities{}, ErrInvalidCapabilities
	}
	capabilities := Capabilities{
		version:          protocol.Version1_2,
		mode:             lengthModeCBC,
		maxPlaintextLen:  maxPlaintextLen,
		maxProtectedLen:  maxProtectedLen,
		explicitNonceLen: blockLen,
		macLen:           macLen,
		blockLen:         blockLen,
	}

	return capabilities, nil
}

// Version returns the protocol version supported by the suite.
func (c Capabilities) Version() protocol.Version {
	return c.version
}

// SupportsVersion reports whether these capabilities describe version.
func (c Capabilities) SupportsVersion(version protocol.Version) bool {
	return c.mode != 0 && c.version == version
}

// MaskLen returns the required ciphertext sample length for record-number
// masking. It is zero when masking is not applicable.
func (c Capabilities) MaskLen() int {
	return c.maskSampleLen
}

// ProtectedLen returns the exact protected payload length for plaintextLen.
func (c Capabilities) ProtectedLen(plaintextLen int) (int, error) {
	if c.mode == 0 || plaintextLen < 0 || plaintextLen > c.maxPlaintextLen {
		return 0, ErrInvalidCapabilities
	}
	if c.mode == lengthModeAEAD {
		return plaintextLen + c.explicitNonceLen + c.tagLen, nil
	}
	unpadded := plaintextLen + c.macLen + 1

	return c.explicitNonceLen + ((unpadded+c.blockLen-1)/c.blockLen)*c.blockLen, nil
}

// PlaintextLenUpperBound validates protectedLen and returns a checked allocation
// bound.
func (c Capabilities) PlaintextLenUpperBound(protectedLen int) (int, error) {
	if c.mode == 0 || protectedLen < 0 || protectedLen > c.maxProtectedLen {
		return 0, ErrInvalidCapabilities
	}

	switch c.mode {
	case lengthModeAEAD:
		return c.aeadPlaintextLen(protectedLen)
	case lengthModeCBC:
		return c.cbcPlaintextLenUpperBound(protectedLen)
	default:
		return 0, ErrInvalidCapabilities
	}
}

func (c Capabilities) aeadPlaintextLen(protectedLen int) (int, error) {
	plaintextLen := protectedLen - c.explicitNonceLen - c.tagLen
	if plaintextLen < 0 || plaintextLen > c.maxPlaintextLen {
		return 0, ErrInvalidCapabilities
	}

	return plaintextLen, nil
}

func (c Capabilities) cbcPlaintextLenUpperBound(protectedLen int) (int, error) {
	bodyLen := protectedLen - c.explicitNonceLen
	if bodyLen < c.blockLen || bodyLen%c.blockLen != 0 {
		return 0, ErrInvalidCapabilities
	}
	upper := bodyLen - c.macLen - 1
	if upper < 0 {
		return 0, ErrInvalidCapabilities
	}
	// CBC padding field and its padding_length byte occupy 1 to 256
	// bytes.
	// https://www.rfc-editor.org/rfc/rfc5246#section-6.2.3.2
	lower := bodyLen - c.macLen - 256
	if lower > c.maxPlaintextLen {
		return 0, ErrInvalidCapabilities
	}
	if upper > c.maxPlaintextLen {
		upper = c.maxPlaintextLen
	}

	return upper, nil
}

// ValidatePlaintextLen checks the actual plaintext length returned by a
// successful Open against the protected length.
func (c Capabilities) ValidatePlaintextLen(protectedLen, plaintextLen int) error {
	upperBound, err := c.PlaintextLenUpperBound(protectedLen)
	if err != nil || plaintextLen < 0 || plaintextLen > upperBound {
		return ErrInvalidCapabilities
	}

	if c.mode == lengthModeAEAD && plaintextLen != upperBound {
		return ErrInvalidCapabilities
	}
	if c.mode == lengthModeCBC {
		paddingLen := protectedLen - c.explicitNonceLen - plaintextLen - c.macLen
		if paddingLen < 1 || paddingLen > 256 {
			return ErrInvalidCapabilities
		}
	}

	return nil
}

// EndpointRole identifies the local endpoint for DTLS 1.2 key derivation.
type EndpointRole uint8

const (
	// EndpointRoleClient derives client write and server read keys.
	EndpointRoleClient EndpointRole = iota + 1
	// EndpointRoleServer derives server write and client read keys.
	EndpointRoleServer
)

// KeyMaterial is borrowed while deriving connection-bound protection.
// Implementations must not modify or retain returned slices.
type KeyMaterial interface {
	MasterSecret() []byte
	ClientRandom() []byte
	ServerRandom() []byte
	Role() EndpointRole
}

// TrafficSecret is borrowed while deriving generation-bound traffic protection.
type TrafficSecret interface {
	// Bytes returns the borrowed secret. Implementations must not modify or retain it.
	Bytes() []byte
}

// Record is the read-only protection view of one record.
type Record interface {
	// Number returns the version-appropriate nonce number.
	RecordNumber() uint64
	// Data returns owned authentication bytes and validates the supplied record length.
	AuthenticationData(recordLen int) ([]byte, error)
}

// Protection seals and opens records. Implementations treat inputs as read-only
// and return caller-owned bytes.
type Protection interface {
	Seal(record Record, plaintext []byte) ([]byte, error)
	// Open authenticates and decrypts protected. It returns
	// ErrAuthenticationFailed for peer-controlled authentication failures.
	// for operational / provider failures it should pick other errors.
	Open(record Record, protected []byte) ([]byte, error)
}

// TrafficProtection adds record-number masking for generation-bound traffic.
type TrafficProtection interface {
	Protection
	// Mask treats sample as read-only and returns caller-owned bytes.
	Mask(sample []byte) ([]byte, error)
}

// ConnectionSuite derives protection bound to both directions of a connection.
type ConnectionSuite interface {
	Suite
	NewConnectionProtection(KeyMaterial) (Protection, error)
}

// TrafficSuite derives directional, generation-bound traffic protection.
type TrafficSuite interface {
	Suite
	NewTrafficProtection(TrafficSecret) (TrafficProtection, error)
}
