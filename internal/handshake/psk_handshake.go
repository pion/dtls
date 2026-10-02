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
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

// FinalizeClientHello binds the client offer to its finalized wire bytes.
// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11
func (t *Transcript) FinalizeClientHello(state *dtlsstate.State13, cfg *dtlsconfig.HandshakeConfig, hello *handshake.MessageClientHello) (*handshake.MessageClientHello, negotiation.ClientHelloSnapshot, error) {
	if cfg.LocalPSKCallback == nil {
		return dtlsflight.FinalizeClientHello(hello, cfg)
	}
	if len(cfg.LocalPSKIdentityHint) == 0 {
		return nil, negotiation.ClientHelloSnapshot{}, dtlserrors.ErrPSKAndIdentityMustBeSetForClient
	}
	if len(state.LocalPSK) == 0 {
		secret, err := cfg.LocalPSKCallback(nil)
		if err != nil {
			return nil, negotiation.ClientHelloSnapshot{}, err
		}
		if len(secret) == 0 {
			return nil, negotiation.ClientHelloSnapshot{}, dtlserrors.ErrPSKNotNegotiated
		}
		state.LocalPSK = bytes.Clone(secret)
	}
	if state.CipherSuite != nil && state.CipherSuite.HashFunc()().Size() != crypto.SHA256.Size() {
		return nil, negotiation.ClientHelloSnapshot{}, dtlserrors.ErrNoAvailablePSKCipherSuite
	}

	return FinalizeClientHelloWithPSKs(hello, cfg, []PSK{{
		Identity: cfg.LocalPSKIdentityHint, Secret: state.LocalPSK, Hash: crypto.SHA256, External: true,
	}}, t)
}

// selectPSK runs before ClientHello enters the transcript, including on retry.
// An invalid binder for a recognized identity is fatal.
// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11
func (c *handshakeContext) selectPSK(hello *handshake.MessageClientHello, raw []byte) error { //nolint:cyclop
	if c.cfg.LocalPSKCallback == nil {
		return nil
	}
	var offer *extension13.OfferedPSKs
	var dhe bool
	for _, value := range hello.Extensions {
		switch ext := value.(type) {
		case *extension13.OfferedPSKs:
			offer = ext
		case *extension13.PSKKeyExchangeModes:
			dhe = slices.Contains(ext.Modes, extension13.PSKDHEKE)
		}
	}
	suite := c.pskCipherSuite(hello)
	c.state.PSK = nil
	if offer == nil || !dhe || suite == nil {
		return c.pskFallback()
	}
	for i, identity := range offer.Identities {
		secret, err := c.cfg.LocalPSKCallback(bytes.Clone(identity.Identity))
		if err != nil {
			return pskHandshakeError(alert.HandshakeFailure, err)
		}
		if len(secret) == 0 {
			continue
		}
		prefix, err := ClientHelloBinderPrefix(raw)
		if err != nil {
			return pskHandshakeError(alert.DecodeError, err)
		}
		transcriptHash, err := pskBinderTranscriptHash(crypto.SHA256, c.transcript, prefix)
		if err != nil {
			return err
		}
		if err = VerifyPSKBinder(crypto.SHA256.New, secret, transcriptHash, offer.Binders[i], true); err != nil {
			return pskHandshakeError(alert.DecryptError, err)
		}
		c.state.CipherSuite = suite
		c.state.PSK = bytes.Clone(secret)
		c.state.PSKIdentity = uint16(i) //nolint:gosec // bounded by uint16.
		c.state.IdentityHint = bytes.Clone(identity.Identity)

		return nil
	}

	return c.pskFallback()
}

func (c *handshakeContext) pskFallback() error {
	if len(c.cfg.LocalCertificates) == 0 && c.cfg.LocalGetCertificate == nil {
		return pskHandshakeError(alert.HandshakeFailure, dtlserrors.ErrPSKNotNegotiated)
	}

	return nil
}

func (c *handshakeContext) pskCipherSuite(hello *handshake.MessageClientHello) dtlsconfig.CipherSuite {
	// HRR commits to a cipher suite and ClientHello2 cannot change it...
	if len(c.transcript.order) != 0 {
		if c.state.CipherSuite.HashFunc()().Size() == crypto.SHA256.Size() {
			return c.state.CipherSuite
		}

		return nil
	}
	for _, id := range hello.CipherSuiteIDs {
		suite, ok := dtlsflight.FindCipherSuiteByID(id, c.cfg.LocalCipherSuites)
		if ok && suite.Capabilities().SupportsVersion(protocol.Version1_3) && suite.HashFunc()().Size() == crypto.SHA256.Size() {
			return suite
		}
	}

	return nil
}

func pskHandshakeError(description alert.Description, err error) error {
	return fmt.Errorf("%w: %w", &alert.Alert{Level: alert.Fatal, Description: description}, err)
}
