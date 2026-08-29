// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package negotiation

import (
	"bytes"
	"fmt"
	"slices"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// SRTPDecision is the validated use_srtp result for one handshake.
type SRTPDecision struct {
	ProtectionProfile       extension.SRTPProtectionProfile
	MasterKeyIdentifier     []byte
	PeerMasterKeyIdentifier []byte
}

// NegotiateSRTP selects the server-preferred profile from the exact offer.
func NegotiateSRTP(snapshot ClientHelloSnapshot, localProfiles []extension.SRTPProtectionProfile, acceptedMKI []byte) (SRTPDecision, error) {
	offer, offered, err := readSRTPOffer(snapshot)
	if err != nil {
		return SRTPDecision{}, err
	}
	if !offered {
		if len(localProfiles) > 0 {
			return SRTPDecision{}, srtpError(dtlserrors.ErrServerNoMatchingSRTPProfile, alert.InsufficientSecurity)
		}

		return SRTPDecision{}, nil
	}

	var profile extension.SRTPProtectionProfile
	for _, candidate := range localProfiles {
		if slices.Contains(offer.ProtectionProfiles, candidate) {
			profile = candidate

			break
		}
	}
	if profile == 0 {
		return SRTPDecision{}, srtpError(dtlserrors.ErrServerNoMatchingSRTPProfile, alert.InsufficientSecurity)
	}

	decision := SRTPDecision{
		ProtectionProfile:       profile,
		PeerMasterKeyIdentifier: bytes.Clone(offer.MasterKeyIdentifier),
	}
	if len(offer.MasterKeyIdentifier) > 0 && bytes.Equal(offer.MasterKeyIdentifier, acceptedMKI) {
		decision.MasterKeyIdentifier = bytes.Clone(offer.MasterKeyIdentifier)
	}

	return decision, nil
}

// ValidateSRTPSelection validates one server selection against the exact offer.
//
//nolint:cyclop
func ValidateSRTPSelection(snapshot ClientHelloSnapshot, responses []extension.Value, localProfiles []extension.SRTPProtectionProfile) (SRTPDecision, error) {
	offer, offered, err := readSRTPOffer(snapshot)
	if err != nil {
		return SRTPDecision{}, err
	}
	if !offered {
		if len(localProfiles) > 0 {
			return SRTPDecision{}, srtpError(dtlserrors.ErrRequestedButNoSRTPExtension, alert.InsufficientSecurity)
		}

		return SRTPDecision{}, nil
	}

	var selection *extension.SRTPSelection
	for _, response := range responses {
		if value, ok := response.(*extension.SRTPSelection); ok {
			selection = value

			break
		}
	}
	if selection == nil {
		return SRTPDecision{}, srtpError(dtlserrors.ErrRequestedButNoSRTPExtension, alert.InsufficientSecurity)
	}
	if !slices.Contains(offer.ProtectionProfiles, selection.ProtectionProfile) || !slices.Contains(localProfiles, selection.ProtectionProfile) {
		return SRTPDecision{}, srtpError(dtlserrors.ErrClientNoMatchingSRTPProfile, alert.IllegalParameter)
	}
	if len(selection.MasterKeyIdentifier) > 0 &&
		!bytes.Equal(selection.MasterKeyIdentifier, offer.MasterKeyIdentifier) {
		return SRTPDecision{}, srtpError(dtlserrors.ErrClientNoMatchingSRTPProfile, alert.IllegalParameter)
	}

	return SRTPDecision{ProtectionProfile: selection.ProtectionProfile, MasterKeyIdentifier: bytes.Clone(selection.MasterKeyIdentifier), PeerMasterKeyIdentifier: bytes.Clone(selection.MasterKeyIdentifier)}, nil
}

// ValidateSRTPRetry requires CH2 to preserve CH1's exact use_srtp payload.
func ValidateSRTPRetry(initial, retry ClientHelloSnapshot) error {
	first, firstPresent := initial.Extension(extension.TypeUseSRTP)
	second, secondPresent := retry.Extension(extension.TypeUseSRTP)
	if firstPresent == secondPresent && bytes.Equal(first.Data, second.Data) {
		return nil
	}

	return srtpError(dtlserrors.ErrInvalidClientHello, alert.IllegalParameter)
}

func readSRTPOffer(snapshot ClientHelloSnapshot) (extension.SRTPOffer, bool, error) {
	raw, ok := snapshot.Extension(extension.TypeUseSRTP)
	if !ok {
		return extension.SRTPOffer{}, false, nil
	}

	var offer extension.SRTPOffer
	if err := offer.UnmarshalData(raw.Data); err != nil {
		return extension.SRTPOffer{}, true, fmt.Errorf("%w: %w", srtpError(dtlserrors.ErrInvalidClientHello, alert.DecodeError), err)
	}

	return offer, true, nil
}

func srtpError(kind error, description alert.Description) error {
	return fmt.Errorf("%w: %w", kind, &alert.Alert{Level: alert.Fatal, Description: description})
}
