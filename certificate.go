// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/tls"
	"net"
	"slices"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/clientcertificate"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension12 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls12"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

// ClientHelloInfo contains information from a ClientHello message in order to
// guide certificate and ECH key selection.
type ClientHelloInfo struct {
	// ServerName indicates the name of the server requested by the client
	// in order to support virtual hosting. ServerName is only set if the
	// client is using SNI (see RFC 4366, Section 3.1).
	ServerName string

	// CipherSuites lists the CipherSuites supported by the client (e.g.
	// TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).
	CipherSuites []cryptosuite.ID

	// RandomBytes stores the client hello random bytes
	RandomBytes [handshake.RandomBytesLength]byte

	// The following offer fields are populated for WithECHGetKeys.
	SupportedCurves   []elliptic.Curve
	SupportedPoints   []elliptic.CurvePointFormat
	SignatureSchemes  []tls.SignatureScheme
	SupportedProtos   []string
	SupportedVersions []protocol.Version
	Extensions        []extension.Type
	HelloRetryRequest bool
	// Conn identifies the DTLS connection. Do not read or write through it
	// while the handshake callback is running.
	Conn    net.Conn
	context func() context.Context
}

// Context returns the handshake context for ECH key selection. It is canceled
// when the handshake ends. Other callback paths currently return nil.
func (c *ClientHelloInfo) Context() context.Context {
	if c.context == nil {
		return nil
	}

	return c.context()
}

func newECHClientHelloInfo(info *dtlsconfig.ClientHelloInfo) *ClientHelloInfo {
	hello := info.Hello
	result := &ClientHelloInfo{RandomBytes: hello.Random.RandomBytes, Conn: info.Conn, context: info.Context, HelloRetryRequest: info.HelloRetryRequest}
	for _, id := range hello.CipherSuiteIDs {
		result.CipherSuites = append(result.CipherSuites, cryptosuite.ID(id))
	}
	for _, ext := range hello.Extensions {
		result.Extensions = append(result.Extensions, ext.ExtensionType())
		result.addECHOfferExtension(ext)
	}
	if len(result.SupportedVersions) == 0 {
		result.SupportedVersions = dtlsconfig.SupportedVersionsRange(protocol.Version1_2, hello.Version)
	}

	return result
}

func (c *ClientHelloInfo) addECHOfferExtension(ext extension.Value) {
	switch ext := ext.(type) {
	case *extension.ServerNameOffer:
		c.ServerName = ext.ServerName
	case *extension.SupportedGroups:
		c.SupportedCurves = slices.Clone(ext.Groups)
	case *extension12.SupportedPointFormats:
		c.SupportedPoints = slices.Clone(ext.PointFormats)
	case *extension.SignatureAlgorithms:
		for _, scheme := range ext.Schemes {
			c.SignatureSchemes = append(c.SignatureSchemes, tls.SignatureScheme(scheme))
		}
	case *extension.ALPNOffer:
		c.SupportedProtos = slices.Clone(ext.Protocols)
	case *extension13.OfferedVersions:
		c.SupportedVersions = slices.Clone(ext.Versions)
	default:
	}
}

// CertificateRequestInfo contains information from a server's
// CertificateRequest message, which is used to demand a certificate and proof
// of control from a client.
type CertificateRequestInfo struct {
	// CertificateTypes lists the certificate types accepted by the server.
	// A nil slice indicates no restriction (DTLS 1.3).
	CertificateTypes []clientcertificate.Type

	// AcceptableCAs contains zero or more, DER-encoded, X.501
	// Distinguished Names. These are the names of root or intermediate CAs
	// that the server wishes the returned certificate to be signed by. An
	// empty slice indicates that the server has no preference.
	AcceptableCAs [][]byte

	// SignatureSchemes lists the signature schemes that the server is
	// willing to verify.
	SignatureSchemes []tls.SignatureScheme
}

// SupportsCertificate returns nil if the provided certificate is supported by
// the server that sent the CertificateRequest. Otherwise, it returns an error
// describing the reason for the incompatibility.
// NOTE: original src:
// https://github.com/golang/go/blob/29b9a328d268d53833d2cc063d1d8b4bf6852675/src/crypto/tls/common.go#L1273
func (cri *CertificateRequestInfo) SupportsCertificate(certificate *tls.Certificate) error {
	var signatureSchemes []signaturehash.Algorithm
	if len(cri.SignatureSchemes) > 0 {
		var err error
		signatureSchemes, err = signaturehash.ParseSignatureSchemes(cri.SignatureSchemes, true)
		if err != nil {
			return err
		}
	}

	return (&dtlsconfig.CertificateRequestInfo{CertificateTypes: cri.CertificateTypes, AcceptableCAs: cri.AcceptableCAs, SignatureSchemes: signatureSchemes, Version: protocol.Version1_3}).SupportsCertificate(certificate)
}
