// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// handshakeRulesThroughClientKeyExchange returns the handshake transcript pull
// rules through ClientKeyExchange (used for CertificateVerify).
func handshakeRulesThroughClientKeyExchange(epoch uint16) []dtlsflight.HandshakeCachePullRule {
	return []dtlsflight.HandshakeCachePullRule{
		{Typ: handshake.TypeClientHello, Epoch: epoch, IsClient: true, Optional: false},
		{Typ: handshake.TypeServerHello, Epoch: epoch, IsClient: false, Optional: false},
		{Typ: handshake.TypeCertificate, Epoch: epoch, IsClient: false, Optional: false},
		{Typ: handshake.TypeServerKeyExchange, Epoch: epoch, IsClient: false, Optional: false},
		{Typ: handshake.TypeCertificateRequest, Epoch: epoch, IsClient: false, Optional: false},
		{Typ: handshake.TypeServerHelloDone, Epoch: epoch, IsClient: false, Optional: false},
		{Typ: handshake.TypeCertificate, Epoch: epoch, IsClient: true, Optional: false},
		{Typ: handshake.TypeClientKeyExchange, Epoch: epoch, IsClient: true, Optional: false},
	}
}

// handshakeRulesThroughClientFinished returns the handshake transcript pull
// rules through the client's Finished message.
func handshakeRulesThroughClientFinished(epoch uint16) []dtlsflight.HandshakeCachePullRule {
	return append(handshakeRulesThroughClientKeyExchange(epoch), dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeCertificateVerify, Epoch: epoch, IsClient: true, Optional: false}, dtlsflight.HandshakeCachePullRule{Typ: handshake.TypeFinished, Epoch: epoch + 1, IsClient: true, Optional: false})
}
