// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"bytes"
	"crypto"
	"crypto/tls"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v3/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

func flight5Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	pkts, dtlsAlert, err := flight5ClientAuthPackets(flightCtx)
	if err != nil {
		return nil, dtlsAlert, err
	}
	pkts = append(pkts, HandshakePacket(&handshake.MessageFinished{}))

	return pkts, nil, nil
}

func flight5ClientAuthPackets(
	flightCtx *handshakeContext,
) ([]*dtlsflight.Outbound, *alert.Alert, error) {
	certificateRequest := flightCtx.state.RemoteCertificateRequest
	if certificateRequest == nil {
		return []*dtlsflight.Outbound{}, nil, nil
	}

	certificate, err := flight5ClientCertificate(flightCtx.cfg, certificateRequest)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
	}
	if len(certificate.Certificate) == 0 {
		return []*dtlsflight.Outbound{HandshakePacket(&handshake.MessageCertificate13{CertificateRequestContext: append([]byte(nil), certificateRequest.CertificateRequestContext...)})}, nil, nil
	}

	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure},
			dtlserrors.ErrInvalidPrivateKey
	}

	signatureScheme, err := signaturehash.SelectSignatureScheme(certificateRequestSignatureSchemes(certificateRequest), signer, protocol.Version1_3)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, err
	}

	return []*dtlsflight.Outbound{
		HandshakePacket(&handshake.MessageCertificate13{
			CertificateRequestContext: append(
				[]byte(nil),
				certificateRequest.CertificateRequestContext...,
			),
			CertificateList: certificateEntries(certificate.Certificate),
		}),
		CertificateVerifyPacket(
			&handshake.MessageCertificateVerify{
				HashAlgorithm:      signatureScheme.Hash,
				SignatureAlgorithm: signatureScheme.Signature,
			},
			signer,
		),
	}, nil, nil
}

func flight5ClientCertificate(cfg *dtlsconfig.HandshakeConfig, request *handshake.MessageCertificateRequest13) (*tls.Certificate, error) {
	requestInfo := &dtlsconfig.CertificateRequestInfo{SignatureSchemes: certificateRequestSignatureSchemes(request), Version: protocol.Version1_3}
	for _, ext := range request.Extensions {
		if authorities, ok := ext.(*extension13.CertificateAuthorities); ok {
			requestInfo.AcceptableCAs = make([][]byte, len(authorities.Authorities))
			for i := range authorities.Authorities {
				requestInfo.AcceptableCAs[i] = bytes.Clone(authorities.Authorities[i])
			}

			break
		}
	}

	certificate, err := cfg.GetClientCertificate(requestInfo)
	if err != nil {
		return nil, err
	}
	if certificate == nil {
		return &tls.Certificate{}, nil
	}

	return certificate, nil
}

func certificateRequestSignatureSchemes(
	request *handshake.MessageCertificateRequest13,
) []signaturehash.Algorithm {
	for _, ext := range request.Extensions {
		if algorithms, ok := ext.(*extension.SignatureAlgorithms); ok {
			return dtlsflight.SignatureSchemes(algorithms.Schemes)
		}
	}

	return nil
}

func certificateEntries(certificates [][]byte) []handshake.CertificateEntry13 {
	entries := make([]handshake.CertificateEntry13, 0, len(certificates))
	for _, certificate := range certificates {
		entries = append(entries, handshake.CertificateEntry13{
			CertificateData: bytes.Clone(certificate),
		})
	}

	return entries
}
