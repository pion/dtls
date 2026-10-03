// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"bytes"
	"crypto"
	"fmt"
	"slices"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

// FinalizeClientHello binds the client offer to its finalized wire bytes.
// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11
func (t *Transcript) FinalizeClientHello(state *dtlsstate.State13, cfg *dtlsconfig.HandshakeConfig, hello *handshake.MessageClientHello) (*handshake.MessageClientHello, negotiation.ClientHelloSnapshot, error) {
	if cfg.GetPSKs == nil {
		if cfg.SetSessionTicket != nil && !slices.ContainsFunc(hello.Extensions, func(value extension.Value) bool {
			return value.ExtensionType() == extension.TypePSKKeyExchangeModes
		}) {
			copyHello := *hello
			copyHello.Extensions = append(slices.Clone(hello.Extensions), &extension13.PSKKeyExchangeModes{
				Modes: []extension13.PSKKeyExchangeMode{extension13.PSKDHEKE},
			})
			hello = &copyHello
		}

		return dtlsflight.FinalizeClientHello(hello, cfg)
	}
	psks, err := cfg.GetPSKs()
	if err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}
	// After HRR, offer only PSKs matching the committed cipher-suite hash.
	// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.4
	if state.CipherSuite != nil {
		psks = slices.DeleteFunc(slices.Clone(psks), func(psk dtlsstate.PSK) bool {
			return psk.Hash.Size() != state.CipherSuite.HashFunc()().Size()
		})
		if len(psks) == 0 {
			return nil, negotiation.ClientHelloSnapshot{}, dtlserrors.ErrNoAvailablePSKCipherSuite
		}
	}
	state.LocalPSKs = psks
	for _, psk := range state.LocalPSKs {
		if len(psk.Identity) == 0 {
			return nil, negotiation.ClientHelloSnapshot{}, dtlserrors.ErrPSKAndIdentityMustBeSetForClient
		}
	}

	return FinalizeClientHelloWithPSKs(hello, cfg, state.LocalPSKs, t)
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
