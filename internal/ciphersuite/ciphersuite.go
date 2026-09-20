// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ciphersuite provides TLS ciphers as registered with IANA.
package ciphersuite

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v4/pkg/crypto/prf"
	"github.com/pion/dtls/v4/pkg/protocol"
)

func ForID(id cryptosuite.ID) cryptosuite.Suite { return builtinCipherSuites[id] }

type suiteMetadata struct {
	id              cryptosuite.ID
	certificateType clientcertificate.Type
	hashFunc        func() hash.Hash
	authentication  cryptosuite.AuthenticationType
	keyExchange     cryptosuite.KeyExchangeAlgorithm
	ecc             bool
}

func (s suiteMetadata) String() string                          { return s.id.String() }
func (s suiteMetadata) ID() cryptosuite.ID                      { return s.id }
func (s suiteMetadata) CertificateType() clientcertificate.Type { return s.certificateType }
func (s suiteMetadata) HashFunc() func() hash.Hash              { return s.hashFunc }
func (s suiteMetadata) AuthenticationType() cryptosuite.AuthenticationType {
	return s.authentication
}
func (s suiteMetadata) KeyExchangeAlgorithm() cryptosuite.KeyExchangeAlgorithm { return s.keyExchange }
func (s suiteMetadata) ECC() bool                                              { return s.ecc }

type protectionAlgorithm12 uint8

const (
	protection12CCM protectionAlgorithm12 = iota + 1
	protection12GCM
	protection12CBC
	protection12ChaCha20Poly1305
)

type suite12 struct {
	suiteMetadata
	algorithm     protectionAlgorithm12
	keyLen        int
	recordMACHash func() hash.Hash
	ccmTagLen     int
}

func newSuite12(id cryptosuite.ID, certificateType clientcertificate.Type, keyExchange cryptosuite.KeyExchangeAlgorithm, hashFunc func() hash.Hash, algorithm protectionAlgorithm12, keyLen int, recordMACHash func() hash.Hash, ccmTagLen int) *suite12 {
	authentication := cryptosuite.AuthenticationTypeCertificate
	if certificateType == 0 {
		authentication = cryptosuite.AuthenticationTypePreSharedKey
	}

	return &suite12{
		suiteMetadata: suiteMetadata{id: id, certificateType: certificateType, hashFunc: hashFunc, authentication: authentication, keyExchange: keyExchange, ecc: keyExchange.Has(cryptosuite.KeyExchangeAlgorithmEcdhe)},
		algorithm:     algorithm,
		keyLen:        keyLen,
		recordMACHash: recordMACHash,
		ccmTagLen:     ccmTagLen,
	}
}

// UsageLimits reports advisory AEAD recommendations for DTLS 1.2.
//
//	| Cipher                                   | Successful encryptions | Authentication failures |
//	| ---------------------------------------- | ---------------------- | ----------------------- |
//	| AES-GCM, DTLS 1.2                        | 23,726,566             | 2^28                    |
//	| ChaCha20-Poly1305                        | MaxUint64*             | 2^36                    |
//	| AES-CCM, 16-byte tag                     | 2^23                   | 11,863,283              |
//	| AES-CCM, 8-byte tag (AES-128 or AES-256) | 2^23                   | 128                     |
//	| AES-CBC with HMAC                        | Unspecified            | Unspecified             |
//
// *ChaCha20's record-number limit is reached first.
//
// AES-GCM, DTLS 1.2: https://www.rfc-editor.org/rfc/rfc9325.html#section-4.4
// ChaCha20 limits: https://www.rfc-editor.org/rfc/rfc9147.html#section-4.5.3
// Encryption bounds: https://www.rfc-editor.org/rfc/rfc8446.html#section-5.5
// ChaCha20, DTLS 1.2 nonce construction: https://www.rfc-editor.org/rfc/rfc7905.html#section-2
// CCM analysis adopted for DTLS 1.2: https://www.rfc-editor.org/rfc/rfc9147.html#appendix-B
// CCM with 8-byte tags: https://www.rfc-editor.org/rfc/rfc9147.html#appendix-B.3
func (s *suite12) UsageLimits() cryptosuite.UsageLimits {
	switch s.algorithm {
	case protection12GCM:
		return cryptosuite.UsageLimits{MaxSealedRecords: 23726566, MaxAuthenticationFailures: 1 << 28}
	case protection12ChaCha20Poly1305:
		return cryptosuite.UsageLimits{MaxSealedRecords: math.MaxUint64, MaxAuthenticationFailures: 1 << 36}
	case protection12CCM:
		failures := uint64(11863283)
		if s.ccmTagLen == ccmTagLength8 {
			failures = 1 << 7
		}

		return cryptosuite.UsageLimits{MaxSealedRecords: 1 << 23, MaxAuthenticationFailures: failures}
	case protection12CBC:
		return cryptosuite.UsageLimits{}
	default:
		return cryptosuite.UsageLimits{}
	}
}

func (s *suite12) Capabilities() cryptosuite.Capabilities {
	switch s.algorithm {
	case protection12CCM:
		return mustAEADCapabilities(protocol.Version1_2, 8, s.ccmTagLen, 0)
	case protection12GCM:
		return mustAEADCapabilities(protocol.Version1_2, 8, 16, 0)
	case protection12CBC:
		return mustCBCCapabilities(s.recordMACHash().Size())
	case protection12ChaCha20Poly1305:
		return mustAEADCapabilities(protocol.Version1_2, 0, 16, 0)
	default:
		return cryptosuite.Capabilities{}
	}
}

type directionalKeys12 struct {
	localKey, localIV, localMAC    []byte
	remoteKey, remoteIV, remoteMAC []byte
}

//nolint:cyclop
func (s *suite12) NewConnectionProtection(
	material cryptosuite.KeyMaterial,
) (cryptosuite.Protection, error) {
	macLen, ivLen := 0, 4
	//nolint:exhaustive // CCM and GCM use the defaults above.
	switch s.algorithm {
	case protection12CBC:
		macLen, ivLen = s.recordMACHash().Size(), 16
	case protection12ChaCha20Poly1305:
		ivLen = 12
	}

	keys, err := prf.GenerateEncryptionKeys(material.MasterSecret(), material.ClientRandom(), material.ServerRandom(), macLen, s.keyLen, ivLen, s.hashFunc)
	if err != nil {
		return nil, err
	}
	directional, err := selectDirectionalKeys12(keys, material.Role())
	if err != nil {
		return nil, err
	}

	var protection cryptosuite.Protection
	switch s.algorithm {
	case protection12CCM:
		protection, err = newCCM(s.ccmTagLen, directional.localKey, directional.localIV, directional.remoteKey, directional.remoteIV)
	case protection12GCM:
		protection, err = newGCM(
			directional.localKey, directional.localIV, directional.remoteKey, directional.remoteIV,
		)
	case protection12CBC:
		protection, err = newCBC(directional.localKey, directional.localIV, directional.localMAC, directional.remoteKey, directional.remoteIV, directional.remoteMAC, s.recordMACHash)
	case protection12ChaCha20Poly1305:
		protection, err = newChaCha20Poly1305(directional.localKey, directional.localIV, directional.remoteKey, directional.remoteIV)
	default:
		return nil, cryptosuite.ErrInvalidCapabilities
	}
	if err != nil {
		return nil, err
	}

	return protection, nil
}

func selectDirectionalKeys12(keys *prf.EncryptionKeys, role cryptosuite.EndpointRole) (directionalKeys12, error) {
	switch role {
	case cryptosuite.EndpointRoleClient:
		return directionalKeys12{localKey: keys.ClientWriteKey, localIV: keys.ClientWriteIV, localMAC: keys.ClientMACKey, remoteKey: keys.ServerWriteKey, remoteIV: keys.ServerWriteIV, remoteMAC: keys.ServerMACKey}, nil
	case cryptosuite.EndpointRoleServer:
		return directionalKeys12{localKey: keys.ServerWriteKey, localIV: keys.ServerWriteIV, localMAC: keys.ServerMACKey, remoteKey: keys.ClientWriteKey, remoteIV: keys.ClientWriteIV, remoteMAC: keys.ClientMACKey}, nil
	default:
		return directionalKeys12{}, dtlserrors.ErrInvalidProtectionInput
	}
}

type protectionAlgorithm13 uint8

const (
	protection13AESGCM protectionAlgorithm13 = iota + 1
	protection13ChaCha20Poly1305
)

type suite13 struct {
	suiteMetadata
	algorithm protectionAlgorithm13
	keyLen    int
}

func newSuite13(
	id cryptosuite.ID,
	hashFunc func() hash.Hash,
	algorithm protectionAlgorithm13,
	keyLen int,
) *suite13 {
	return &suite13{suiteMetadata: suiteMetadata{id: id, hashFunc: hashFunc, authentication: cryptosuite.AuthenticationTypeAnonymous, keyExchange: cryptosuite.KeyExchangeAlgorithmNone, ecc: true}, algorithm: algorithm, keyLen: keyLen}
}

// UsageLimits reports advisory AEAD recommendations for DTLS 1.3.
// AES-GCM, DTLS 1.3 is limited to 23,726,566 successful encryptions and 2^36 authentication failures.
// ChaCha20-Poly1305 is limited to MaxUint64 successful encryptions (record-number limit) and 2^36 authentication failures.
//
// DTLS 1.3 AEAD limits: https://www.rfc-editor.org/rfc/rfc9147.html#section-4.5.3
// ChaCha20 limits adopted from DTLS 1.3: https://www.rfc-editor.org/rfc/rfc9147.html#section-4.5.3
// Encryption bounds: https://www.rfc-editor.org/rfc/rfc8446.html#section-5.5
func (s *suite13) UsageLimits() cryptosuite.UsageLimits {
	maxSealed := uint64(23726566)
	if s.algorithm == protection13ChaCha20Poly1305 {
		maxSealed = math.MaxUint64
	}

	return cryptosuite.UsageLimits{MaxSealedRecords: maxSealed, MaxAuthenticationFailures: 1 << 36}
}

func (s *suite13) Capabilities() cryptosuite.Capabilities {
	return mustAEADCapabilities(
		protocol.Version1_3,
		0,
		tls13AESGCMTagLen,
		tls13SequenceNumberMaskSampleLen,
	)
}

func (s *suite13) NewTrafficProtection(
	trafficSecret cryptosuite.TrafficSecret,
) (cryptosuite.TrafficProtection, error) {
	switch s.algorithm {
	case protection13AESGCM:
		return newAESGCMRecordTrafficProtection13(s.hashFunc, trafficSecret.Bytes(), s.keyLen)
	case protection13ChaCha20Poly1305:
		return newChaCha20Poly1305RecordTrafficProtection13(s.hashFunc, trafficSecret.Bytes())
	default:
		return nil, cryptosuite.ErrInvalidCapabilities
	}
}

//nolint:gochecknoglobals
var builtinCipherSuites = map[cryptosuite.ID]cryptosuite.Suite{
	cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:              newSuite12(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM, clientcertificate.ECDSASign, cryptosuite.KeyExchangeAlgorithmEcdhe, sha256.New, protection12CCM, 16, nil, ccmTagLength),
	cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:            newSuite12(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, clientcertificate.ECDSASign, cryptosuite.KeyExchangeAlgorithmEcdhe, sha256.New, protection12CCM, 16, nil, ccmTagLength8),
	cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       newSuite12(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, clientcertificate.ECDSASign, cryptosuite.KeyExchangeAlgorithmEcdhe, sha256.New, protection12GCM, 16, nil, 0),
	cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         newSuite12(cryptosuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, clientcertificate.RSASign, cryptosuite.KeyExchangeAlgorithmEcdhe, sha256.New, protection12GCM, 16, nil, 0),
	cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       newSuite12(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, clientcertificate.ECDSASign, cryptosuite.KeyExchangeAlgorithmEcdhe, sha512.New384, protection12GCM, 32, nil, 0),
	cryptosuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         newSuite12(cryptosuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, clientcertificate.RSASign, cryptosuite.KeyExchangeAlgorithmEcdhe, sha512.New384, protection12GCM, 32, nil, 0),
	cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          newSuite12(cryptosuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, clientcertificate.ECDSASign, cryptosuite.KeyExchangeAlgorithmEcdhe, sha256.New, protection12CBC, 32, sha1.New, 0),
	cryptosuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:            newSuite12(cryptosuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, clientcertificate.RSASign, cryptosuite.KeyExchangeAlgorithmEcdhe, sha256.New, protection12CBC, 32, sha1.New, 0),
	cryptosuite.TLS_PSK_WITH_AES_128_CCM:                      newSuite12(cryptosuite.TLS_PSK_WITH_AES_128_CCM, 0, cryptosuite.KeyExchangeAlgorithmPsk, sha256.New, protection12CCM, 16, nil, ccmTagLength),
	cryptosuite.TLS_PSK_WITH_AES_128_CCM_8:                    newSuite12(cryptosuite.TLS_PSK_WITH_AES_128_CCM_8, 0, cryptosuite.KeyExchangeAlgorithmPsk, sha256.New, protection12CCM, 16, nil, ccmTagLength8),
	cryptosuite.TLS_PSK_WITH_AES_256_CCM_8:                    newSuite12(cryptosuite.TLS_PSK_WITH_AES_256_CCM_8, 0, cryptosuite.KeyExchangeAlgorithmPsk, sha256.New, protection12CCM, 32, nil, ccmTagLength8),
	cryptosuite.TLS_PSK_WITH_AES_128_GCM_SHA256:               newSuite12(cryptosuite.TLS_PSK_WITH_AES_128_GCM_SHA256, 0, cryptosuite.KeyExchangeAlgorithmPsk, sha256.New, protection12GCM, 16, nil, 0),
	cryptosuite.TLS_PSK_WITH_AES_128_CBC_SHA256:               newSuite12(cryptosuite.TLS_PSK_WITH_AES_128_CBC_SHA256, 0, cryptosuite.KeyExchangeAlgorithmPsk, sha256.New, protection12CBC, 16, sha256.New, 0),
	cryptosuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:         newSuite12(cryptosuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, 0, cryptosuite.KeyExchangeAlgorithmPsk|cryptosuite.KeyExchangeAlgorithmEcdhe, sha256.New, protection12CBC, 16, sha256.New, 0),
	cryptosuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: newSuite12(cryptosuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, clientcertificate.ECDSASign, cryptosuite.KeyExchangeAlgorithmEcdhe, sha256.New, protection12ChaCha20Poly1305, 32, nil, 0),
	cryptosuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   newSuite12(cryptosuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, clientcertificate.RSASign, cryptosuite.KeyExchangeAlgorithmEcdhe, sha256.New, protection12ChaCha20Poly1305, 32, nil, 0),
	cryptosuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:         newSuite12(cryptosuite.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256, 0, cryptosuite.KeyExchangeAlgorithmPsk, sha256.New, protection12ChaCha20Poly1305, 32, nil, 0),
	cryptosuite.TLS_AES_128_GCM_SHA256:                        newSuite13(cryptosuite.TLS_AES_128_GCM_SHA256, sha256.New, protection13AESGCM, tls13AES128GCMKeyLen),
	cryptosuite.TLS_AES_256_GCM_SHA384:                        newSuite13(cryptosuite.TLS_AES_256_GCM_SHA384, sha512.New384, protection13AESGCM, tls13AES256GCMKeyLen),
	cryptosuite.TLS_CHACHA20_POLY1305_SHA256:                  newSuite13(cryptosuite.TLS_CHACHA20_POLY1305_SHA256, sha256.New, protection13ChaCha20Poly1305, 0),
}
