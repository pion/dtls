// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"hash"
	"slices"

	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/crypto/keyschedule"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

const (
	labelResBinder = "res binder"
	labelExtBinder = "ext binder"
)

// PSKBinderVerifyData computes a DTLS 1.3 binder over the truncated ClientHello
// transcript hash.
//
// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11.2
// https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1
// https://www.rfc-editor.org/rfc/rfc9147.html#section-5.9
func PSKBinderVerifyData(hashFunc func() hash.Hash, psk, transcriptHash []byte, external bool) ([]byte, error) {
	if len(psk) == 0 {
		return nil, dtlserrors.ErrLengthMismatch
	}
	earlySecret, err := deriveEarlySecret(hashFunc, psk)
	if err != nil {
		return nil, err
	}
	label := labelResBinder
	if external {
		label = labelExtBinder
	}
	binderKey, err := keyschedule.DeriveSecret(hashFunc, earlySecret, label, nil)
	if err != nil {
		return nil, err
	}

	return finishedVerifyData(hashFunc, binderKey, transcriptHash)
}

// VerifyPSKBinder verifies the selected identity's binder in constant time.
//
// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11
func VerifyPSKBinder(hashFunc func() hash.Hash, psk, transcriptHash, binder []byte, external bool) error {
	expected, err := PSKBinderVerifyData(hashFunc, psk, transcriptHash, external)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, binder) {
		return dtlserrors.ErrVerifyDataMismatch
	}

	return nil
}

// FinalizeClientHelloWithPSKs adds a psk_dhe_ke offer, applies the configured
// ClientHello hook, and computes binders over the resulting message.
//
// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11.2
func FinalizeClientHelloWithPSKs(
	base *handshake.MessageClientHello,
	cfg *dtlsconfig.HandshakeConfig,
	psks []dtlsstate.PSK,
	transcript *Transcript,
) (*handshake.MessageClientHello, negotiation.ClientHelloSnapshot, error) {
	clientHello, err := clientHelloWithPSKs(base, psks)
	if err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}
	clientHello, _, err = dtlsflight.FinalizeClientHello(clientHello, cfg)
	if err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}
	if err = populatePSKBinders(clientHello, psks, transcript); err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}

	raw, err := (&handshake.Handshake{Message: clientHello}).Marshal()
	if err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}
	var snapshots negotiation.ClientHelloSnapshots
	if err = snapshots.RecordWire(raw); err != nil {
		return nil, negotiation.ClientHelloSnapshot{}, err
	}

	return clientHello, snapshots.Current(), nil
}

func populatePSKBinders(hello *handshake.MessageClientHello, psks []dtlsstate.PSK, transcript *Transcript) error { //nolint:cyclop
	// the shared finalizer has already decoded and validated the hooked hello.
	if len(hello.Extensions) == 0 {
		return dtlserrors.ErrPreSharedKeyFormat
	}
	offer, ok := hello.Extensions[len(hello.Extensions)-1].(*extension13.OfferedPSKs)
	if !ok || len(offer.Identities) != len(psks) {
		return dtlserrors.ErrPreSharedKeyFormat
	}
	// Hooks may restrict the offer to either supported mode.
	// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.9
	if !slices.ContainsFunc(hello.Extensions, func(value extension.Value) bool {
		modes, ok := value.(*extension13.PSKKeyExchangeModes)

		return ok && len(modes.Modes) > 0 && !slices.ContainsFunc(modes.Modes, func(mode extension13.PSKKeyExchangeMode) bool {
			return mode != extension13.PSKDHEKE && mode != extension13.PSKKE
		})
	}) {
		return dtlserrors.ErrPreSharedKeyFormat
	}
	raw, err := (&handshake.Handshake{Message: hello}).Marshal()
	if err != nil {
		return err
	}
	canonical, err := canonicalHandshake(raw)
	if err != nil {
		return err
	}
	prefix := truncatePSKBinders(canonical, offer)
	transcriptHashes := make(map[crypto.Hash][]byte, 2)
	for i, psk := range psks {
		identity := offer.Identities[i]
		if !bytes.Equal(identity.Identity, psk.Identity) || identity.ObfuscatedTicketAge != psk.ObfuscatedTicketAge || len(offer.Binders[i]) != psk.Hash.Size() {
			return dtlserrors.ErrPreSharedKeyFormat
		}
		transcriptHash, cached := transcriptHashes[psk.Hash]
		if !cached {
			transcriptHash, err = pskBinderTranscriptHash(psk.Hash, transcript, prefix)
			if err != nil {
				return err
			}
			transcriptHashes[psk.Hash] = transcriptHash
		}
		offer.Binders[i], err = PSKBinderVerifyData(psk.Hash.New, psk.Secret, transcriptHash, psk.External)
		if err != nil {
			return err
		}
	}

	return nil
}

// A retry binder covers message_hash(ClientHello1), HRR, and the ClientHello2 prefix.
//
// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11.2
// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.1
func pskBinderTranscriptHash(hashID crypto.Hash, transcript *Transcript, prefix []byte) ([]byte, error) {
	if transcript == nil {
		return nil, dtlserrors.ErrHandshakeTranscriptHashNotSelected
	}
	if len(transcript.order) == 0 {
		hasher := hashID.New()
		_, _ = hasher.Write(prefix) // hash.Hash.Write never returns an error.

		return hasher.Sum(nil), nil
	}
	if !transcript.helloRetryApplied || len(transcript.order) != 2 || transcript.h == nil || transcript.h.Size() != hashID.Size() {
		return nil, dtlserrors.ErrHandshakeTranscriptHelloRetryRequestInvalid
	}

	return transcript.SnapshotHashWithSuffix(prefix)
}

// ClientHelloBinderPrefix extracts a binder prefix from a complete, reassembled
// DTLS ClientHello.
//
// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.11.2
// https://www.rfc-editor.org/rfc/rfc9147.html#section-5.2
func ClientHelloBinderPrefix(raw []byte) ([]byte, error) {
	canonical, err := canonicalHandshake(raw)
	if err != nil {
		return nil, err
	}
	if handshake.Type(canonical[0]) != handshake.TypeClientHello {
		return nil, dtlserrors.ErrInvalidHandshakeTranscriptMessage
	}
	var hello handshake.MessageClientHello
	if err := hello.Unmarshal(canonical[tlsHandshakeHeaderLength:]); err != nil {
		return nil, err
	}
	if len(hello.Extensions) == 0 {
		return nil, dtlserrors.ErrPreSharedKeyFormat
	}
	offer, ok := hello.Extensions[len(hello.Extensions)-1].(*extension13.OfferedPSKs)
	if !ok {
		return nil, dtlserrors.ErrPreSharedKeyFormat
	}

	return truncatePSKBinders(canonical, offer), nil
}

func truncatePSKBinders(canonical []byte, offer *extension13.OfferedPSKs) []byte {
	bindersSize := 2
	for _, binder := range offer.Binders {
		bindersSize += 1 + len(binder)
	}
	end := len(canonical) - bindersSize

	return canonical[:end:end]
}

func clientHelloWithPSKs(base *handshake.MessageClientHello, psks []dtlsstate.PSK) (*handshake.MessageClientHello, error) { //nolint:cyclop
	if base == nil || len(psks) == 0 {
		return nil, dtlserrors.ErrPreSharedKeyFormat
	}
	offer := &extension13.OfferedPSKs{}
	for _, psk := range psks {
		if len(psk.Identity) == 0 {
			return nil, dtlserrors.ErrPSKAndIdentityMustBeSetForClient
		}
		if len(psk.Secret) == 0 || (psk.Hash != crypto.SHA256 && psk.Hash != crypto.SHA384) || !psk.Hash.Available() || (psk.External && psk.ObfuscatedTicketAge != 0) {
			return nil, dtlserrors.ErrPreSharedKeyFormat
		}
		offer.Identities = append(offer.Identities, extension13.PSKIdentity{Identity: bytes.Clone(psk.Identity), ObfuscatedTicketAge: psk.ObfuscatedTicketAge})
		offer.Binders = append(offer.Binders, make([]byte, psk.Hash.Size()))
	}
	clientHello := *base
	modes := []extension13.PSKKeyExchangeMode{extension13.PSKDHEKE, extension13.PSKKE}
	clientHello.Extensions = make([]extension.Value, 0, len(base.Extensions)+2)
	for _, value := range base.Extensions {
		if previous, ok := value.(*extension13.PSKKeyExchangeModes); ok {
			modes = slices.Clone(previous.Modes)
		}
		if value != nil && (value.ExtensionType() == extension.TypePreSharedKey || value.ExtensionType() == extension.TypePSKKeyExchangeModes) {
			continue
		}
		clientHello.Extensions = append(clientHello.Extensions, value)
	}
	if slices.ContainsFunc(psks, func(psk dtlsstate.PSK) bool { return !psk.External }) {
		modes = []extension13.PSKKeyExchangeMode{extension13.PSKDHEKE}
	}
	clientHello.Extensions = append(clientHello.Extensions, &extension13.PSKKeyExchangeModes{Modes: modes}, offer)

	return &clientHello, nil
}
