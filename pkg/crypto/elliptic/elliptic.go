// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package elliptic provides elliptic curve cryptography for DTLS
package elliptic

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"fmt"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
)

// X25519KeySize is the size in bytes of an X25519 public key, private key, or
// shared secret.
const X25519KeySize = 32

const (
	// X25519MLKEM768ClientPublicKeySize is the encoded client key share size.
	X25519MLKEM768ClientPublicKeySize = mlkem.EncapsulationKeySize768 + X25519KeySize
	// X25519MLKEM768ServerPublicKeySize is the encoded server key share size.
	X25519MLKEM768ServerPublicKeySize = mlkem.CiphertextSize768 + X25519KeySize
	// X25519MLKEM768ClientPrivateKeySize is the encoded client private key size.
	X25519MLKEM768ClientPrivateKeySize = mlkem.SeedSize + X25519KeySize
	// X25519MLKEM768ServerPrivateKeySize is the encoded server private key size.
	X25519MLKEM768ServerPrivateKeySize = mlkem.SharedKeySize + X25519KeySize
	// X25519MLKEM768SharedSecretSize is the hybrid shared secret size.
	X25519MLKEM768SharedSecretSize = mlkem.SharedKeySize + X25519KeySize
)

// CurvePointFormat is used to represent the IANA registered curve points
//
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-9
type CurvePointFormat byte

// CurvePointFormat enums.
const (
	CurvePointFormatUncompressed CurvePointFormat = 0
)

// Keypair is a Curve with a Private/Public Keypair.
type Keypair struct {
	Curve      Curve
	PublicKey  []byte
	PrivateKey []byte //nolint:gosec // no real risk of exporting the private key.
}

// CurveType is used to represent the IANA registered curve types for TLS
//
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10
type CurveType byte

// CurveType enums.
const (
	CurveTypeNamedCurve CurveType = 0x03
)

// CurveTypes returns all known curves.
func CurveTypes() map[CurveType]struct{} {
	return map[CurveType]struct{}{
		CurveTypeNamedCurve: {},
	}
}

// Curve is used to represent the IANA registered curves for TLS
//
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type Curve uint16

// Curve enums.
const (
	P256           Curve = 0x0017
	P384           Curve = 0x0018
	X25519         Curve = 0x001d
	X25519MLKEM768 Curve = 0x11ec
)

func (c Curve) String() string {
	switch c {
	case P256:
		return "P-256"
	case P384:
		return "P-384"
	case X25519:
		return "X25519"
	case X25519MLKEM768:
		return "X25519MLKEM768"
	}

	return fmt.Sprintf("%#x", uint16(c))
}

// Curves returns all curves we implement.
func Curves() map[Curve]bool {
	return map[Curve]bool{
		X25519:         true,
		P256:           true,
		P384:           true,
		X25519MLKEM768: true,
	}
}

// GenerateKeypair generates a keypair for the given Curve.
func GenerateKeypair(curve Curve) (*Keypair, error) {
	if curve == X25519MLKEM768 {
		return generateX25519MLKEM768ClientKeypair()
	}

	return generateECDHKeypair(curve)
}

// GenerateKeypairForPeer generates a keypair for the given Curve and peer
// public key. Classical ECDHE groups ignore peerPublicKey, while hybrid KEM
// groups need it to produce their response key share.
func GenerateKeypairForPeer(curve Curve, peerPublicKey []byte) (*Keypair, error) {
	if curve == X25519MLKEM768 {
		return generateX25519MLKEM768ServerKeypair(peerPublicKey)
	}

	return generateECDHKeypair(curve)
}

func generateECDHKeypair(curve Curve) (*Keypair, error) {
	ec, err := curve.toECDH()
	if err != nil {
		return nil, err
	}

	sk, err := ec.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	pk := sk.PublicKey()

	return &Keypair{
		Curve:      curve,
		PublicKey:  pk.Bytes(), // NIST: SEC1 uncompressed (04||X||Y); X25519: 32 bytes
		PrivateKey: sk.Bytes(), // Scalar suitable for ecdh.NewPrivateKey
	}, nil
}

func generateX25519MLKEM768ClientKeypair() (*Keypair, error) {
	mlkemSecretKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}

	x25519Keypair, err := generateECDHKeypair(X25519)
	if err != nil {
		return nil, err
	}

	publicKey := make([]byte, 0, X25519MLKEM768ClientPublicKeySize)
	publicKey = append(publicKey, mlkemSecretKey.EncapsulationKey().Bytes()...)
	publicKey = append(publicKey, x25519Keypair.PublicKey...)

	privateKey := make([]byte, 0, X25519MLKEM768ClientPrivateKeySize)
	privateKey = append(privateKey, mlkemSecretKey.Bytes()...)
	privateKey = append(privateKey, x25519Keypair.PrivateKey...)

	return &Keypair{
		Curve:      X25519MLKEM768,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func generateX25519MLKEM768ServerKeypair(peerPublicKey []byte) (*Keypair, error) {
	if len(peerPublicKey) != X25519MLKEM768ClientPublicKeySize {
		return nil, dtlserrors.ErrLengthMismatch
	}

	mlkemEncapsulationKey, err := mlkem.NewEncapsulationKey768(peerPublicKey[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, err
	}
	mlkemSharedKey, mlkemCiphertext := mlkemEncapsulationKey.Encapsulate()

	x25519Keypair, err := generateECDHKeypair(X25519)
	if err != nil {
		return nil, err
	}

	publicKey := make([]byte, 0, X25519MLKEM768ServerPublicKeySize)
	publicKey = append(publicKey, mlkemCiphertext...)
	publicKey = append(publicKey, x25519Keypair.PublicKey...)

	privateKey := make([]byte, 0, X25519MLKEM768ServerPrivateKeySize)
	privateKey = append(privateKey, mlkemSharedKey...)
	privateKey = append(privateKey, x25519Keypair.PrivateKey...)

	return &Keypair{
		Curve:      X25519MLKEM768,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// toECDH returns the crypto/ecdh curve for our enum.
func (c Curve) toECDH() (ecdh.Curve, error) {
	switch c {
	case X25519:
		return ecdh.X25519(), nil
	case P256:
		return ecdh.P256(), nil
	case P384:
		return ecdh.P384(), nil
	default:
		return nil, dtlserrors.ErrInvalidNamedCurve
	}
}
