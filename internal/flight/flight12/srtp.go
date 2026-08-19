// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight12

import (
	"bytes"
	"fmt"
	"slices"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/internal/extensionnegotiation"
	dtlsflight "github.com/pion/dtls/v3/internal/flight"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

type srtpDecision struct {
	profile extension.SRTPProtectionProfile
	mki     []byte
	peerMKI []byte
}

func readSRTPOffer(snapshot extensionnegotiation.ClientHelloSnapshot) (extension.SRTPOffer, bool, error) {
	raw, ok := snapshot.Extension(extension.TypeUseSRTP)
	if !ok {
		return extension.SRTPOffer{}, false, nil
	}

	var offer extension.SRTPOffer
	if err := offer.UnmarshalData(raw.Data); err != nil {
		return extension.SRTPOffer{}, true, fmt.Errorf("%w: %w",
			srtpAlert(dtlserrors.ErrInvalidClientHello, alert.DecodeError), err)
	}

	return offer, true, nil
}

func negotiateServerSRTP(
	snapshot extensionnegotiation.ClientHelloSnapshot,
	cfg *dtlsconfig.HandshakeConfig,
) (srtpDecision, error) {
	offer, offered, err := readSRTPOffer(snapshot)
	if err != nil || !offered {
		return srtpDecision{}, err
	}

	profile, ok := dtlsflight.FindMatchingSRTPProfile(cfg.LocalSRTPProtectionProfiles, offer.ProtectionProfiles)
	if !ok {
		return srtpDecision{}, srtpAlert(dtlserrors.ErrServerNoMatchingSRTPProfile, alert.InsufficientSecurity)
	}

	decision := srtpDecision{profile: profile, peerMKI: bytes.Clone(offer.MasterKeyIdentifier)}
	if len(offer.MasterKeyIdentifier) > 0 && bytes.Equal(offer.MasterKeyIdentifier, cfg.LocalSRTPMasterKeyIdentifier) {
		decision.mki = bytes.Clone(offer.MasterKeyIdentifier)
	}

	return decision, nil
}

func validateSRTPSelection(
	snapshot extensionnegotiation.ClientHelloSnapshot,
	responses []extension.Value,
	localProfiles []extension.SRTPProtectionProfile,
) (srtpDecision, error) {
	offer, offered, err := readSRTPOffer(snapshot)
	if err != nil {
		return srtpDecision{}, err
	}

	if !offered {
		return srtpDecision{}, nil
	}
	var selection *extension.SRTPSelection
	for _, response := range responses {
		if value, ok := response.(*extension.SRTPSelection); ok {
			selection = value

			break
		}
	}
	if selection == nil {
		return srtpDecision{}, srtpAlert(dtlserrors.ErrRequestedButNoSRTPExtension, alert.InsufficientSecurity)
	}
	if !slices.Contains(offer.ProtectionProfiles, selection.ProtectionProfile) ||
		!slices.Contains(localProfiles, selection.ProtectionProfile) {
		return srtpDecision{}, srtpAlert(dtlserrors.ErrClientNoMatchingSRTPProfile, alert.IllegalParameter)
	}
	if len(selection.MasterKeyIdentifier) > 0 &&
		!bytes.Equal(selection.MasterKeyIdentifier, offer.MasterKeyIdentifier) {
		return srtpDecision{}, srtpAlert(dtlserrors.ErrClientNoMatchingSRTPProfile, alert.IllegalParameter)
	}

	return srtpDecision{
		profile: selection.ProtectionProfile,
		mki:     bytes.Clone(selection.MasterKeyIdentifier),
		peerMKI: bytes.Clone(selection.MasterKeyIdentifier),
	}, nil
}

func validateServerSRTP(
	snapshot extensionnegotiation.ClientHelloSnapshot,
	responses []extension.Value,
	localProfiles []extension.SRTPProtectionProfile,
	want srtpDecision,
) error {
	got, err := validateSRTPSelection(snapshot, responses, localProfiles)
	if err != nil {
		return err
	}
	if got.profile != want.profile || !bytes.Equal(got.mki, want.mki) {
		return srtpAlert(dtlserrors.ErrInvalidServerHello, alert.InternalError)
	}

	return nil
}

func appendSRTPSelection(extensions []extension.Value, decision srtpDecision) []extension.Value {
	if decision.profile == 0 {
		return extensions
	}

	return append(extensions, &extension.SRTPSelection{
		ProtectionProfile:   decision.profile,
		MasterKeyIdentifier: bytes.Clone(decision.mki),
	})
}

func commitSRTP(state *dtlsstate.State12, profile extension.SRTPProtectionProfile, peerMKI []byte) {
	if profile != 0 {
		state.RemoteSRTPMasterKeyIdentifier = bytes.Clone(peerMKI)
	}
	state.SetSRTPProtectionProfile(profile)
}

func srtpAlert(kind error, description alert.Description) error {
	return fmt.Errorf("%w: %w", kind, &alert.Alert{Level: alert.Fatal, Description: description})
}
