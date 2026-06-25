// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ciphersuite provides TLS Ciphers as registered with the IANA
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
package ciphersuite

import (
	"fmt"
	"hash"
	"slices"

	"github.com/pion/dtls/v3/internal/ciphersuite/types"
	"github.com/pion/dtls/v3/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

// CipherSuite is the interface that all DTLS CipherSuites satisfy. The public
// dtls.CipherSuite interface mirrors it for the package's exported API.
type CipherSuite interface {
	String() string
	ID() ID
	CertificateType() clientcertificate.Type
	HashFunc() func() hash.Hash
	AuthenticationType() AuthenticationType
	KeyExchangeAlgorithm() KeyExchangeAlgorithm
	ECC() bool
	Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error
	IsInitialized() bool
	Encrypt(pkt *recordlayer.RecordLayer, raw []byte) ([]byte, error)
	Decrypt(h recordlayer.Header, in []byte) ([]byte, error)
}

// ID is an ID for our supported CipherSuites.
type ID uint16

func (i ID) String() string { //nolint:cyclop
	switch i {
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case TLS_PSK_WITH_AES_128_CCM:
		return "TLS_PSK_WITH_AES_128_CCM"
	case TLS_PSK_WITH_AES_128_CCM_8:
		return "TLS_PSK_WITH_AES_128_CCM_8"
	case TLS_PSK_WITH_AES_256_CCM_8:
		return "TLS_PSK_WITH_AES_256_CCM_8"
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return "TLS_PSK_WITH_AES_128_GCM_SHA256"
	case TLS_PSK_WITH_AES_128_CBC_SHA256:
		return "TLS_PSK_WITH_AES_128_CBC_SHA256"
	case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"
	case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"
	case TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	default:
		return fmt.Sprintf("unknown(%v)", uint16(i))
	}
}

// Supported Cipher Suites.
const (
	// AES-128-CCM.
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM   ID = 0xc0ac // nolint: revive,staticcheck
	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 ID = 0xc0ae // nolint: revive,staticcheck

	// AES-128-GCM-SHA256.
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ID = 0xc02b // nolint: revive,staticcheck
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   ID = 0xc02f // nolint: revive,staticcheck

	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ID = 0xc02c // nolint: revive,staticcheck
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   ID = 0xc030 // nolint: revive,staticcheck
	// AES-256-CBC-SHA.
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA ID = 0xc00a // nolint: revive,staticcheck
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA   ID = 0xc014 // nolint: revive,staticcheck

	TLS_PSK_WITH_AES_128_CCM        ID = 0xc0a4 // nolint: revive,staticcheck
	TLS_PSK_WITH_AES_128_CCM_8      ID = 0xc0a8 // nolint: revive,staticcheck
	TLS_PSK_WITH_AES_256_CCM_8      ID = 0xc0a9 // nolint: revive,staticcheck
	TLS_PSK_WITH_AES_128_GCM_SHA256 ID = 0x00a8 // nolint: revive,staticcheck
	TLS_PSK_WITH_AES_128_CBC_SHA256 ID = 0x00ae // nolint: revive,staticcheck

	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 ID = 0xC037 // nolint: revive,staticcheck

	// ChaCha20-Poly1305-SHA256.
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 ID = 0xcca9 // nolint: revive,staticcheck
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   ID = 0xcca8 // nolint: revive,staticcheck
	TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         ID = 0xccab // nolint: revive,staticcheck

	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       ID = 0x1301 // nolint: revive,staticcheck
	TLS_AES_256_GCM_SHA384       ID = 0x1302 // nolint: revive,staticcheck
	TLS_CHACHA20_POLY1305_SHA256 ID = 0x1303 // nolint: revive,staticcheck
)

// AuthenticationType controls what authentication method is using during the handshake.
type AuthenticationType = types.AuthenticationType

// AuthenticationType Enums.
const (
	AuthenticationTypeCertificate  AuthenticationType = types.AuthenticationTypeCertificate
	AuthenticationTypePreSharedKey AuthenticationType = types.AuthenticationTypePreSharedKey
	AuthenticationTypeAnonymous    AuthenticationType = types.AuthenticationTypeAnonymous
)

// KeyExchangeAlgorithm controls what exchange algorithm was chosen.
type KeyExchangeAlgorithm = types.KeyExchangeAlgorithm

// KeyExchangeAlgorithm Bitmask.
const (
	KeyExchangeAlgorithmNone  KeyExchangeAlgorithm = types.KeyExchangeAlgorithmNone
	KeyExchangeAlgorithmPsk   KeyExchangeAlgorithm = types.KeyExchangeAlgorithmPsk
	KeyExchangeAlgorithmEcdhe KeyExchangeAlgorithm = types.KeyExchangeAlgorithmEcdhe
)

func ForID(id ID, customCiphers func() []CipherSuite) CipherSuite { //nolint:cyclop
	switch id { //nolint:exhaustive
	case TLS_AES_128_GCM_SHA256:
		return NewTLSAes128GcmSha256()
	case TLS_AES_256_GCM_SHA384:
		return NewTLSAes256GcmSha384()
	case TLS_CHACHA20_POLY1305_SHA256:
		return NewTLSChacha20Poly1305Sha256()
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
		return NewTLSEcdheEcdsaWithAes128Ccm()
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
		return NewTLSEcdheEcdsaWithAes128Ccm8()
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return &TLSEcdheEcdsaWithAes128GcmSha256{}
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return &TLSEcdheRsaWithAes128GcmSha256{}
	case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return &TLSEcdheEcdsaWithAes256CbcSha{}
	case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return &TLSEcdheRsaWithAes256CbcSha{}
	case TLS_PSK_WITH_AES_128_CCM:
		return NewTLSPskWithAes128Ccm()
	case TLS_PSK_WITH_AES_128_CCM_8:
		return NewTLSPskWithAes128Ccm8()
	case TLS_PSK_WITH_AES_256_CCM_8:
		return NewTLSPskWithAes256Ccm8()
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		return &TLSPskWithAes128GcmSha256{}
	case TLS_PSK_WITH_AES_128_CBC_SHA256:
		return &TLSPskWithAes128CbcSha256{}
	case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return &TLSEcdheEcdsaWithAes256GcmSha384{}
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return &TLSEcdheRsaWithAes256GcmSha384{}
	case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
		return NewTLSEcdhePskWithAes128CbcSha256()
	case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return &TLSEcdheEcdsaWithChacha20Poly1305Sha256{}
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return &TLSEcdheRsaWithChacha20Poly1305Sha256{}
	case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return &TLSPskWithChacha20Poly1305Sha256{}
	}

	if customCiphers != nil {
		for _, c := range customCiphers() {
			if c.ID() == id {
				return c
			}
		}
	}

	return nil
}

func SupportedVersions(id ID) []protocol.Version {
	switch id { //nolint:exhaustive
	case TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256:
		return []protocol.Version{protocol.Version1_3}
	case TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_PSK_WITH_AES_128_CCM,
		TLS_PSK_WITH_AES_128_CCM_8,
		TLS_PSK_WITH_AES_256_CCM_8,
		TLS_PSK_WITH_AES_128_GCM_SHA256,
		TLS_PSK_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
		return []protocol.Version{protocol.Version1_2}
	default:
		return []protocol.Version{protocol.Version1_2}
	}
}

func SupportedVersionIDs(id ID) []uint16 {
	versions := SupportedVersions(id)
	ids := make([]uint16, 0, len(versions))
	for _, version := range versions {
		ids = append(ids, uint16(version.Major)<<8|uint16(version.Minor))
	}

	return ids
}

func IDSupportsVersion(id ID, version protocol.Version) bool {
	return slices.ContainsFunc(SupportedVersions(id), version.Equal)
}
