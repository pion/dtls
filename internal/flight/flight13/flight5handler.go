// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"crypto"
	"crypto/tls"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

func flight5Generate(
	_ dtlsflight.Conn,
	flightCtx *handshakeContext,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	pkts, dtlsAlert, err := flight5ClientAuthPackets(flightCtx)
	if err != nil {
		return nil, dtlsAlert, err
	}
	pkts = append(pkts, HandshakePacket(&handshake.MessageFinished{}))
	pkts[0].ResetLocalSequenceNumber = true

	return pkts, nil, nil
}

func flight5ClientAuthPackets(
	flightCtx *handshakeContext,
) ([]*dtlsflight.Packet, *alert.Alert, error) {
	certificateRequest, ok, err := flight5CertificateRequest(flightCtx.cache)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}, err
	}
	if !ok {
		return []*dtlsflight.Packet{}, nil, nil
	}

	certificate, err := flight5ClientCertificate(flightCtx.cfg, certificateRequest)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, err
	}
	if len(certificate.Certificate) == 0 {
		return []*dtlsflight.Packet{
			HandshakePacket(&handshake.MessageCertificate13{
				CertificateRequestContext: append(
					[]byte(nil),
					certificateRequest.CertificateRequestContext...,
				),
			}),
		}, nil, nil
	}

	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure},
			dtlserrors.ErrInvalidPrivateKey
	}

	signatureScheme, err := signaturehash.SelectSignatureScheme13(
		certificateRequestSignatureSchemes(certificateRequest),
		signer,
	)
	if err != nil {
		return nil, &alert.Alert{Level: alert.Fatal, Description: alert.InsufficientSecurity}, err
	}

	return []*dtlsflight.Packet{
		HandshakePacket(&handshake.MessageCertificate13{
			CertificateRequestContext: append(
				[]byte(nil),
				certificateRequest.CertificateRequestContext...,
			),
			CertificateList: certificateEntries13(certificate.Certificate),
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

func flight5CertificateRequest(
	cache *dtlsflight.Cache,
) (*handshake.MessageCertificateRequest13, bool, error) {
	if cache == nil {
		return nil, false, nil
	}

	items := cache.Pull(dtlsflight.HandshakeCachePullRule{
		Typ:      handshake.TypeCertificateRequest,
		Epoch:    EpochHandshake,
		IsClient: false,
		Optional: true,
	})
	if len(items) == 0 || items[0] == nil {
		return nil, false, nil
	}

	item := items[0]
	header := &handshake.Header{}
	if err := header.Unmarshal(item.Data); err != nil {
		return nil, false, err
	}
	if !validFlight5CertificateRequestItem(item, header) {
		return nil, false, dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}

	request := &handshake.MessageCertificateRequest13{}
	if err := request.Unmarshal(item.Data[handshake.HeaderLength:]); err != nil {
		return nil, false, err
	}

	return request, true, nil
}

func validFlight5CertificateRequestItem(
	item *dtlsflight.HandshakeCacheItem,
	header *handshake.Header,
) bool {
	return header.Type == handshake.TypeCertificateRequest &&
		header.MessageSequence == item.MessageSequence &&
		header.FragmentOffset == 0 &&
		header.FragmentLength == header.Length &&
		len(item.Data) == handshake.HeaderLength+int(header.Length)
}

func flight5ClientCertificate(
	cfg *dtlsconfig.HandshakeConfig,
	request *handshake.MessageCertificateRequest13,
) (*tls.Certificate, error) {
	requestInfo := &dtlsconfig.CertificateRequestInfo{
		SignatureSchemes: certificateRequestSignatureSchemes(request),
	}
	for _, ext := range request.Extensions {
		if authorities, ok := ext.(*extension.CertificateAuthorities); ok {
			requestInfo.AcceptableCAs = authorities.Authorities

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
		if algorithms, ok := ext.(*extension.SupportedSignatureAlgorithms); ok {
			return algorithms.SignatureHashAlgorithms
		}
	}

	return nil
}

func certificateEntries13(certificates [][]byte) []handshake.CertificateEntry13 {
	entries := make([]handshake.CertificateEntry13, 0, len(certificates))
	for _, certificate := range certificates {
		entries = append(entries, handshake.CertificateEntry13{
			CertificateData: append([]byte(nil), certificate...),
		})
	}

	return entries
}
