// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"bytes"
	"crypto"
	"fmt"
	"slices"
	"time"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	"github.com/pion/dtls/v4/internal/ech"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	dtlsflight13 "github.com/pion/dtls/v4/internal/flight/flight13"
	dtlscrypto "github.com/pion/dtls/v4/internal/handshakecrypto"
	"github.com/pion/dtls/v4/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

// FinalizeClientHello binds the client offer to its finalized wire bytes.
// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11
func (t *Transcript) FinalizeClientHello(state *dtlsstate.State13, cfg *dtlsconfig.HandshakeConfig, hello *handshake.MessageClientHello, conn dtlsflight.Conn) (*handshake.MessageClientHello, negotiation.ClientHelloSnapshot, error) {
	if cfg.ECHConfigList != nil {
		return t.finalizeECHClientHello(state, cfg, hello)
	}
	psks := state.LocalPSKs
	if !t.helloRetryApplied {
		var err error
		psks, err = clientPSKs(cfg, hello, conn)
		if err != nil {
			return nil, negotiation.ClientHelloSnapshot{}, err
		}
	}
	// HRR commits to a hash. Incompatible tickets can be dropped for a full handshake.
	if state.CipherSuite != nil {
		psks = slices.DeleteFunc(slices.Clone(psks), func(psk dtlsstate.PSK) bool {
			return psk.Hash.Size() != state.CipherSuite.HashFunc()().Size()
		})
		if len(psks) == 0 && cfg.GetPSKs != nil {
			return nil, negotiation.ClientHelloSnapshot{}, dtlserrors.ErrNoAvailablePSKCipherSuite
		}
	}
	state.LocalPSKs = psks
	if t.helloRetryApplied && state.EarlyDataStatus == dtlsstate.EarlyDataReady {
		state.EarlyDataStatus = dtlsstate.EarlyDataRejected
		state.TrafficKeys.Discard(dtlsflight13.EpochEarlyData)
	}
	if len(psks) != 0 {
		return t.finalizeEarlyClientHello(state, cfg, hello)
	}

	return finalizeClientHelloWithoutPSK(hello, cfg)
}

func (t *Transcript) finalizeECHClientHello(state *dtlsstate.State13, cfg *dtlsconfig.HandshakeConfig, hello *handshake.MessageClientHello) (*handshake.MessageClientHello, negotiation.ClientHelloSnapshot, error) {
	if cfg.GetPSKs != nil || len(state.LocalPSKs) != 0 {
		return nil, negotiation.ClientHelloSnapshot{}, ech.ErrUnsupported
	}
	if state.ECH != nil {
		return finalizeECHRetry(state, cfg, hello)
	}
	final, _, err := dtlsflight.FinalizeClientHello(hello, cfg)
	if err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}
	body, err := final.Marshal()
	if err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}
	context, err := ech.NewClientHello(cfg.ECHConfigList, body)
	if err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}
	outer := &handshake.MessageClientHello{}
	if err = outer.Unmarshal(context.Outer); err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}
	outer, snapshot, err := negotiation.FinalizeClientHello(outer, nil)
	if err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}
	if err := t.initECHInner(context.Inner, uint16(state.HandshakeSendSequence)); err != nil { //nolint:gosec // Handshake sequence numbers are bounded by the wire format.
		return nil, negotiation.ClientHelloSnapshot{}, err
	}
	state.ECH = context

	return outer, snapshot, nil
}

func finalizeECHRetry(state *dtlsstate.State13, cfg *dtlsconfig.HandshakeConfig, hello *handshake.MessageClientHello) (*handshake.MessageClientHello, negotiation.ClientHelloSnapshot, error) {
	if state.ECH.Rejected {
		return dtlsflight.FinalizeClientHello(hello, cfg)
	}
	if !state.ECH.Accepted {
		return nil, negotiation.ClientHelloSnapshot{}, ech.ErrUnsupported
	}
	inner, snapshot, err := dtlsflight.FinalizeClientHello(hello, cfg)
	if err != nil {
		return nil, snapshot, err
	}
	if err = negotiation.ValidateClientHelloRetry(state.LocalClientHelloSnapshots.Initial(), snapshot, state.HelloRetryRequest); err != nil {
		return nil, snapshot, err
	}
	body, err := inner.Marshal()
	if err != nil {
		return nil, snapshot, err
	}
	if err := state.ECH.RetryClientHello(body); err != nil {
		return nil, snapshot, err
	}
	outer := &handshake.MessageClientHello{}
	if err := outer.Unmarshal(state.ECH.Outer); err != nil {
		return nil, snapshot, err
	}

	return outer, snapshot, nil
}

func finalizeClientHelloWithoutPSK(hello *handshake.MessageClientHello, cfg *dtlsconfig.HandshakeConfig) (*handshake.MessageClientHello, negotiation.ClientHelloSnapshot, error) {
	copyHello := *hello
	copyHello.Extensions = slices.DeleteFunc(slices.Clone(hello.Extensions), func(value extension.Value) bool {
		return value.ExtensionType() == extension.TypePreSharedKey || value.ExtensionType() == extension.TypeEarlyData
	})
	hello = &copyHello
	if cfg.SetSessionTicket != nil && !slices.ContainsFunc(hello.Extensions, func(value extension.Value) bool {
		return value.ExtensionType() == extension.TypePSKKeyExchangeModes
	}) {
		hello.Extensions = append(hello.Extensions, &extension13.PSKKeyExchangeModes{
			Modes: []extension13.PSKKeyExchangeMode{extension13.PSKDHEKE},
		})
	}

	return dtlsflight.FinalizeClientHello(hello, cfg)
}

func clientPSKs(cfg *dtlsconfig.HandshakeConfig, hello *handshake.MessageClientHello, conn dtlsflight.Conn) ([]dtlsstate.PSK, error) { //nolint:cyclop
	var psks []dtlsstate.PSK
	if cfg.GetPSKs != nil {
		var err error
		psks, err = cfg.GetPSKs()
		if err != nil {
			return nil, err
		}
	}
	if cfg.GetSessionTicket == nil {
		return psks, nil
	}
	psk, err := cfg.GetSessionTicket(conn.SessionKey(), cfg.ServerName)
	if err != nil || psk == nil {
		return psks, err
	}
	if !slices.ContainsFunc(cfg.LocalCipherSuites, func(suite dtlsconfig.CipherSuite) bool {
		return suite.Capabilities().SupportsVersion(protocol.Version1_3) && slices.Contains(hello.CipherSuiteIDs, uint16(suite.ID())) && suite.HashFunc()().Size() == psk.Hash.Size()
	}) || (len(psk.PeerCertificates) == 0 && cfg.GetPSKs == nil) {
		return psks, nil
	}
	if len(psk.PeerCertificates) != 0 && !cfg.InsecureSkipVerify {
		algorithms := cfg.LocalCertSignatureSchemes
		if len(algorithms) == 0 {
			algorithms = cfg.LocalSignatureSchemes
		}
		if _, err := dtlscrypto.VerifyServerCert(psk.PeerCertificates, cfg.RootCAs, cfg.ServerName, algorithms); err != nil {
			return psks, nil //nolint:nilerr // unusable cached certificate triggers a full handshake.
		}
	}

	return append([]dtlsstate.PSK{*psk}, psks...), nil
}

// selectPSK runs before ClientHello enters the transcript, including on retry.
// An invalid binder for a recognized identity is fatal.
// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11
func (c *handshakeContext) selectPSK(hello *handshake.MessageClientHello, raw []byte) error { //nolint:cyclop
	if c.cfg.SelectPSK == nil && c.cfg.GetSessionTicket == nil {
		return nil
	}
	var offer *extension13.OfferedPSKs
	var dhe, ke bool
	for _, value := range hello.Extensions {
		switch ext := value.(type) {
		case *extension13.OfferedPSKs:
			offer = ext
		case *extension13.PSKKeyExchangeModes:
			dhe = slices.Contains(ext.Modes, extension13.PSKDHEKE)
			ke = slices.Contains(ext.Modes, extension13.PSKKE)
		}
	}
	c.state.PSK = nil
	c.state.PSKOnly = false
	// prefer DHE whenever a common group exists, this can require a retry.
	dhe = dhe && slices.ContainsFunc(c.cfg.EllipticCurves, func(group elliptic.Curve) bool {
		return slices.Contains(c.state.RemoteGroups, group)
	})
	if offer == nil || (!dhe && !ke) {
		return c.pskFallback()
	}
	i, psk, err := c.selectOfferedPSK(hello, offer, dhe)
	if err != nil {
		return pskHandshakeError(alert.HandshakeFailure, err)
	}
	if psk == nil {
		return c.pskFallback()
	}
	if i < 0 || i >= len(offer.Identities) {
		return pskHandshakeError(alert.HandshakeFailure, dtlserrors.ErrPSKIdentity)
	}
	secret, hashID := psk.Secret, psk.Hash
	suite := c.pskCipherSuite(hello, hashID)
	if suite == nil {
		return c.pskFallback()
	}
	prefix, err := ClientHelloBinderPrefix(raw)
	if err != nil {
		return pskHandshakeError(alert.DecodeError, err)
	}
	transcriptHash, err := pskBinderTranscriptHash(hashID, c.transcript, prefix)
	if err != nil {
		return err
	}
	if err = VerifyPSKBinder(hashID.New, secret, transcriptHash, offer.Binders[i], psk.External); err != nil {
		return pskHandshakeError(alert.DecryptError, err)
	}
	c.state.PSKOnly = !dhe
	if c.state.PSKOnly {
		c.state.KeyAgreementSecret = make([]byte, hashID.Size())
	}
	c.state.CipherSuite = suite
	c.state.PSK = bytes.Clone(secret)
	c.state.PSKIdentity = uint16(i) //nolint:gosec // bounded by uint16.
	c.state.IdentityHint = bytes.Clone(offer.Identities[i].Identity)
	if i == 0 && psk.Ticket != nil && slices.ContainsFunc(hello.Extensions, func(value extension.Value) bool {
		return value.ExtensionType() == extension.TypeEarlyData
	}) {
		c.state.EarlyDataPSK = psk
		c.state.EarlyClientHello = bytes.Clone(raw)
		psk.ObfuscatedTicketAge = offer.Identities[0].ObfuscatedTicketAge
	}

	return nil
}

func (c *handshakeContext) selectOfferedPSK(hello *handshake.MessageClientHello, offer *extension13.OfferedPSKs, dhe bool) (int, *dtlsstate.PSK, error) {
	if dhe && c.cfg.ClientAuth == dtlsconfig.NoClientCert && c.cfg.GetSessionTicket != nil {
		if i, psk, err := c.selectSessionTicket(hello, offer); err != nil || psk != nil {
			return i, psk, err
		}
	}
	if c.cfg.SelectPSK == nil {
		return 0, nil, nil
	}
	identities := make([][]byte, len(offer.Identities))
	for i, identity := range offer.Identities {
		identities[i] = identity.Identity
	}
	i, secret, hashID, err := c.cfg.SelectPSK(identities)
	if err != nil || len(secret) == 0 {
		return i, nil, err
	}

	return i, &dtlsstate.PSK{Secret: secret, Hash: hashID, External: true}, nil
}

func (c *handshakeContext) selectSessionTicket(hello *handshake.MessageClientHello, offer *extension13.OfferedPSKs) (int, *dtlsstate.PSK, error) {
	if len(offer.Identities) > c.cfg.PSKIdentityLimit {
		return 0, nil, dtlserrors.ErrTooManyPSKIdentities
	}
	for i, identity := range offer.Identities {
		psk, err := c.cfg.GetSessionTicket(identity.Identity, c.state.ServerName)
		if err != nil {
			return 0, nil, err
		}
		if psk != nil && bytes.Equal(psk.Identity, identity.Identity) && c.pskCipherSuite(hello, psk.Hash) != nil {
			return i, psk, nil
		}
	}

	return 0, nil, nil
}

func (c *handshakeContext) pskFallback() error {
	if len(c.cfg.LocalCertificates) == 0 && c.cfg.LocalGetCertificate == nil {
		return pskHandshakeError(alert.HandshakeFailure, dtlserrors.ErrPSKNotNegotiated)
	}

	return nil
}

func (c *handshakeContext) pskCipherSuite(hello *handshake.MessageClientHello, hashID crypto.Hash) dtlsconfig.CipherSuite {
	// HRR commits to a cipher suite and ClientHello2 cannot change it...
	if len(c.transcript.order) != 0 {
		if c.state.CipherSuite.HashFunc()().Size() == hashID.Size() {
			return c.state.CipherSuite
		}

		return nil
	}
	for _, id := range hello.CipherSuiteIDs {
		suite, ok := dtlsflight.FindCipherSuiteByID(id, c.cfg.LocalCipherSuites)
		if ok && suite.Capabilities().SupportsVersion(protocol.Version1_3) && suite.HashFunc()().Size() == hashID.Size() {
			return suite
		}
	}

	return nil
}

func pskHandshakeError(description alert.Description, err error) error {
	return fmt.Errorf("%w: %w", &alert.Alert{Level: alert.Fatal, Description: description}, err)
}

func (t *Transcript) finalizeEarlyClientHello(state *dtlsstate.State13, cfg *dtlsconfig.HandshakeConfig, hello *handshake.MessageClientHello) (*handshake.MessageClientHello, negotiation.ClientHelloSnapshot, error) {
	copyHello := *hello
	copyHello.Extensions = slices.DeleteFunc(slices.Clone(hello.Extensions), func(value extension.Value) bool {
		return value.ExtensionType() == extension.TypeEarlyData
	})
	suite := earlyTicketSuite(state.LocalPSKs[0], cfg)
	if !t.helloRetryApplied && suite != nil {
		copyHello.Extensions = append(copyHello.Extensions, &extension13.EarlyData{})
	}
	final, snapshot, err := FinalizeClientHelloWithPSKs(&copyHello, cfg, state.LocalPSKs, t)
	if err != nil || !snapshot.Offered(extension.TypeEarlyData) {
		return final, snapshot, err
	}
	if t.helloRetryApplied || suite == nil || !slices.Contains(final.CipherSuiteIDs, uint16(suite.ID())) {
		return nil, negotiation.ClientHelloSnapshot{}, dtlserrors.ErrInvalidClientHello
	}
	raw, err := (&handshake.Handshake{Message: final}).Marshal()
	if err == nil {
		err = InitEarlyRecordProtection(state, suite, state.LocalPSKs[0].Secret, raw)
	}
	if err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}
	state.NegotiatedProtocol = state.LocalPSKs[0].Ticket.NegotiatedProtocol
	state.EarlyDataStatus = dtlsstate.EarlyDataReady
	state.EarlyDataLimit = state.LocalPSKs[0].Ticket.MaxEarlyDataSize

	return final, snapshot, nil
}

func earlyTicketSuite(psk dtlsstate.PSK, cfg *dtlsconfig.HandshakeConfig) cryptosuite.TrafficSuite {
	if !cfg.EnableEarlyData || psk.Ticket == nil || psk.Ticket.MaxEarlyDataSize == 0 {
		return nil
	}
	if psk.Ticket.NegotiatedProtocol != "" && !slices.Contains(cfg.SupportedProtocols, psk.Ticket.NegotiatedProtocol) {
		return nil
	}
	for _, suite := range cfg.LocalCipherSuites {
		if suite.ID() == psk.Ticket.CipherSuite {
			trafficSuite, _ := suite.(cryptosuite.TrafficSuite)

			return trafficSuite
		}
	}

	return nil
}

func (s *fsm13) acceptEarlyData() error {
	state := s.state
	defer func() { state.EarlyDataPSK, state.EarlyClientHello = nil, nil }()
	psk := state.EarlyDataPSK
	if psk == nil || s.transcript.helloRetryApplied || s.cfg.ClaimEarlyData == nil {
		return nil
	}
	suite := earlyTicketSuite(*psk, s.cfg)
	if suite == nil {
		return nil
	}
	ticket := psk.Ticket
	if !freshEarlyTicket(ticket, psk.ObfuscatedTicketAge-ticket.AgeAdd, time.Now(), state.CipherSuite.ID(), state.NegotiatedProtocol) || s.cfg.MaxEarlyDataSize < ticket.MaxEarlyDataSize {
		return nil
	}
	fresh, err := s.cfg.ClaimEarlyData(bytes.Clone(psk.Identity), ticket.CreatedAt.Add(time.Duration(ticket.Lifetime)*time.Second))
	if err != nil || !fresh {
		return nil //nolint:nilerr // failures means early data is rejected, resumption is continued
	}
	if err := InitEarlyRecordProtection(state, suite, psk.Secret, state.EarlyClientHello); err != nil {
		return err
	}
	state.EarlyDataStatus = dtlsstate.EarlyDataAccepted
	state.EarlyDataLimit = ticket.MaxEarlyDataSize

	return nil
}

func freshEarlyTicket(ticket *dtlsstate.SessionTicket, clientAge uint32, now time.Time, suite cryptosuite.ID, protocol string) bool {
	age := now.Sub(ticket.CreatedAt)
	// https://datatracker.ietf.org/doc/html/rfc9846#section-8.3
	skew := age - time.Duration(clientAge)*time.Millisecond

	return ticket.NegotiatedProtocol == protocol && ticket.CipherSuite == suite && age >= 0 && age < time.Duration(ticket.Lifetime)*time.Second &&
		skew >= -10*time.Second && skew <= 10*time.Second
}
