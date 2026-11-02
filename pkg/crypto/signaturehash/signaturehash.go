// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package signaturehash provides the SignatureHashAlgorithm as defined in TLS 1.2
package signaturehash

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/pkg/crypto/hash"
	"github.com/pion/dtls/v4/pkg/crypto/signature"
	"github.com/pion/dtls/v4/pkg/protocol"
)

// Algorithm is a signature/hash algorithm pairs which may be used in
// digital signatures.
//
// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
type Algorithm struct {
	Hash      hash.Algorithm
	Signature signature.Algorithm
}

// Algorithms returns signature algorithms compatible with DTLS 1.2 / TLS 1.2.
//
// IMPORTANT: order in this slice determines priority used by SelectSignatureScheme.
//
// Order follows industry standard preference (ECDSA-first) as used by OpenSSL,
// BoringSSL, Firefox, Chrome, and other major TLS implementations.
func Algorithms() []Algorithm {
	return []Algorithm{
		// ECDSA schemes (modern, efficient - industry standard preference)
		{hash.SHA256, signature.ECDSA},
		{hash.SHA384, signature.ECDSA},
		{hash.SHA512, signature.ECDSA},

		// Ed25519
		{hash.Ed25519, signature.Ed25519},

		// RSA-PSS RSAE schemes (DTLS 1.3 compatible with standard RSA certs)
		// Note: We only offer RSA_PSS_RSAE variants (0x0804-0x0806), not RSA_PSS_PSS
		// (0x0809-0x080b). RSA-PSS certificates with OID id-RSASSA-PSS are virtually
		// unused in the real world and are not allowed by the CA/Browser Forum Baseline
		// Requirements for WebPKI. We avoid unnecessary complexity for certificates that
		// don't exist in practice, following the pragmatic approach of Go's crypto/tls
		// and BoringSSL: target real-world WebPKI use cases rather than RFC completeness.
		// RSA_PSS_PSS schemes are parsed for wire-format compatibility but never negotiated.
		{hash.SHA256, signature.RSA_PSS_RSAE_SHA256},
		{hash.SHA384, signature.RSA_PSS_RSAE_SHA384},
		{hash.SHA512, signature.RSA_PSS_RSAE_SHA512},
		// {hash.SHA256, signature.RSA_PSS_PSS_SHA256},
		// {hash.SHA384, signature.RSA_PSS_PSS_SHA384},
		// {hash.SHA512, signature.RSA_PSS_PSS_SHA512},

		// RSA PKCS#1 v1.5 schemes (legacy, DTLS 1.2)
		{hash.SHA256, signature.RSA},
		{hash.SHA384, signature.RSA},
		{hash.SHA512, signature.RSA},
	}
}

// SelectSignatureScheme returns the most preferred compatible scheme for version.
func SelectSignatureScheme(sigs []Algorithm, privateKey crypto.PrivateKey, version protocol.Version) (Algorithm, error) {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return Algorithm{}, dtlserrors.ErrInvalidPrivateKey
	}

	is13 := version == protocol.Version1_3
	for _, ss := range sigs {
		if !ss.validForVersion(version) {
			continue
		}
		if ss.isCompatible(signer, is13) {
			return ss, nil
		}
	}

	return Algorithm{}, dtlserrors.ErrNoAvailableSignatureSchemes
}

func (a Algorithm) validForVersion(version protocol.Version) bool {
	if a.Signature.IsUnsupported() {
		return false
	}
	if version != protocol.Version1_3 {
		return !a.Signature.IsPSS()
	}

	return a.Signature != signature.RSA && !a.Hash.Insecure() && a.Hash != hash.SHA224
}

// isCompatible checks that given private key is compatible with the signature scheme.
func (a *Algorithm) isCompatible(signer crypto.Signer, is13 bool) bool {
	switch key := signer.Public().(type) {
	case ed25519.PublicKey:
		return a.Signature == signature.Ed25519
	case *ecdsa.PublicKey:
		return a.Signature == signature.ECDSA && (!is13 || a.matchesECDSACurve(key))
	case *rsa.PublicKey:
		// RSA keys are compatible with both PKCS#1 v1.5 and PSS signatures
		return a.Signature == signature.RSA || a.Signature.IsPSS()
	default:
		return false
	}
}

func (a Algorithm) matchesECDSACurve(key *ecdsa.PublicKey) bool {
	return (key.Curve == elliptic.P256() && a.Hash == hash.SHA256) ||
		(key.Curve == elliptic.P384() && a.Hash == hash.SHA384) ||
		(key.Curve == elliptic.P521() && a.Hash == hash.SHA512)
}

// ParseSignatureSchemes translates []tls.SignatureScheme to []signatureHashAlgorithm.
// It returns default signature scheme list if no SignatureScheme is passed.
// This function handles both TLS 1.2 byte-split encoding and TLS 1.3 PSS full uint16 schemes.
func ParseSignatureSchemes(sigs []tls.SignatureScheme, insecureHashes bool) ([]Algorithm, error) {
	if len(sigs) == 0 {
		return Algorithms(), nil
	}
	out := []Algorithm{}
	for _, ss := range sigs {
		var alg Algorithm
		err := alg.Unmarshal(ss)
		if err != nil {
			return nil, err
		}

		if alg.Hash.Insecure() && !insecureHashes {
			continue
		}

		out = append(out, alg)
	}

	if len(out) == 0 {
		return nil, dtlserrors.ErrNoAvailableSignatureSchemes
	}

	return out, nil
}

// FromCertificate maps x509.SignatureAlgorithm to the corresponding Algorithm type.
func FromCertificate(cert *x509.Certificate) (Algorithm, error) {
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSAPSS:
		return Algorithm{Hash: hash.SHA256, Signature: signature.RSA_PSS_RSAE_SHA256}, nil
	case x509.SHA384WithRSAPSS:
		return Algorithm{Hash: hash.SHA384, Signature: signature.RSA_PSS_RSAE_SHA384}, nil
	case x509.SHA512WithRSAPSS:
		return Algorithm{Hash: hash.SHA512, Signature: signature.RSA_PSS_RSAE_SHA512}, nil
	case x509.SHA256WithRSA:
		return Algorithm{Hash: hash.SHA256, Signature: signature.RSA}, nil
	case x509.SHA384WithRSA:
		return Algorithm{Hash: hash.SHA384, Signature: signature.RSA}, nil
	case x509.SHA512WithRSA:
		return Algorithm{Hash: hash.SHA512, Signature: signature.RSA}, nil
	case x509.SHA1WithRSA:
		return Algorithm{Hash: hash.SHA1, Signature: signature.RSA}, nil
	default:
		return fromNonRSACertificate(cert.SignatureAlgorithm)
	}
}

func fromNonRSACertificate(algorithm x509.SignatureAlgorithm) (Algorithm, error) {
	switch algorithm {
	case x509.ECDSAWithSHA256:
		return Algorithm{Hash: hash.SHA256, Signature: signature.ECDSA}, nil
	case x509.ECDSAWithSHA384:
		return Algorithm{Hash: hash.SHA384, Signature: signature.ECDSA}, nil
	case x509.ECDSAWithSHA512:
		return Algorithm{Hash: hash.SHA512, Signature: signature.ECDSA}, nil
	case x509.PureEd25519:
		return Algorithm{Hash: hash.None, Signature: signature.Ed25519}, nil
	case x509.ECDSAWithSHA1:
		return Algorithm{Hash: hash.SHA1, Signature: signature.ECDSA}, nil
	default:
		return Algorithm{}, dtlserrors.ErrInvalidSignatureAlgorithm
	}
}

// Unmarshal translates a tls.SignatureScheme to a Algorithm.
// This function handles both TLS 1.2 byte-split encoding and
// TLS 1.3 PSS full uint16 schemes.
func (a *Algorithm) Unmarshal(sigScheme tls.SignatureScheme) error {
	if signature.Algorithm(sigScheme).IsPSS() {
		// TLS 1.3 PSS scheme - full uint16 is the signature algorithm
		a.Signature = signature.Algorithm(sigScheme)
		a.Hash = hash.ExtractHashFromPSS(uint16(sigScheme))
		if a.Hash == hash.None {
			return dtlserrors.ErrInvalidHashAlgorithm
		}
	} else {
		// TLS 1.2 style - split into hash (high byte) and signature (low byte)
		a.Signature = signature.Algorithm(sigScheme & 0xFF)
		a.Hash = hash.Algorithm(sigScheme >> 8)
	}

	// Validate signature algorithm
	if _, ok := signature.Algorithms()[a.Signature]; !ok {
		return dtlserrors.ErrInvalidSignatureAlgorithm
	}

	// Validate hash algorithm
	if _, ok := hash.Algorithms()[a.Hash]; !ok || (ok && a.Hash == hash.None) {
		return dtlserrors.ErrInvalidHashAlgorithm
	}

	return nil
}

// Marshal encodes the Algorithm to the correct TLS 1.2 byte-split or
// the TLS 1.3 PSS full uint16 schemes.
func (a *Algorithm) Marshal() []byte {
	out := make([]byte, 2)
	// For PSS schemes, write the full uint16 SignatureScheme value.
	// For other schemes, write hash (high byte) + signature (low byte) in TLS 1.2 style.
	if a.Signature.IsPSS() {
		// TLS 1.3 PSS: full uint16 is the signature scheme
		scheme := uint16(a.Signature)
		out[0] = byte(scheme >> 8)
		out[1] = byte(scheme & 0xFF)
	} else {
		// TLS 1.2 style: hash byte + signature byte
		out[0] = byte(a.Hash)      //nolint:gosec // G115: TLS 1.2 hash algorithm field is defined as 1 byte.
		out[1] = byte(a.Signature) //nolint:gosec // G115: TLS 1.2 signature algorithm field is defined as 1 byte.
	}

	return out
}
