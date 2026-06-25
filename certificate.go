// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"crypto/tls"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// ClientHelloInfo contains information from a ClientHello message in order to
// guide application logic in the GetCertificate.
type ClientHelloInfo struct {
	// ServerName indicates the name of the server requested by the client
	// in order to support virtual hosting. ServerName is only set if the
	// client is using SNI (see RFC 4366, Section 3.1).
	ServerName string

	// CipherSuites lists the CipherSuites supported by the client (e.g.
	// TLS_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256).
	CipherSuites []CipherSuiteID

	// RandomBytes stores the client hello random bytes
	RandomBytes [handshake.RandomBytesLength]byte
}

// CertificateRequestInfo contains information from a server's
// CertificateRequest message, which is used to demand a certificate and proof
// of control from a client.
type CertificateRequestInfo struct {
	// AcceptableCAs contains zero or more, DER-encoded, X.501
	// Distinguished Names. These are the names of root or intermediate CAs
	// that the server wishes the returned certificate to be signed by. An
	// empty slice indicates that the server has no preference.
	AcceptableCAs [][]byte
}

// SupportsCertificate returns nil if the provided certificate is supported by
// the server that sent the CertificateRequest. Otherwise, it returns an error
// describing the reason for the incompatibility.
// NOTE: original src:
// https://github.com/golang/go/blob/29b9a328d268d53833d2cc063d1d8b4bf6852675/src/crypto/tls/common.go#L1273
func (cri *CertificateRequestInfo) SupportsCertificate(c *tls.Certificate) error {
	return dtlsconfig.SupportsCertificate(cri.AcceptableCAs, c)
}
