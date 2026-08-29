// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"

	dtlsciphersuite "github.com/pion/dtls/v3/internal/ciphersuite"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	dtlsflight13 "github.com/pion/dtls/v3/internal/flight/flight13"
	dtlsstate "github.com/pion/dtls/v3/internal/state"
	cryptosuite "github.com/pion/dtls/v3/pkg/crypto/ciphersuite"
)

func InitHandshakeRecordProtection(state *dtlsstate.State13) error {
	if state == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}

	return initRecordProtectionFromTrafficSecrets(
		state,
		dtlsflight13.EpochHandshake,
		state.KeySchedule.HandshakeTraffic,
		false,
	)
}

// InitApplicationRecordProtection installs DTLS 1.3 application record
// protection from the stored application traffic secrets.
func InitApplicationRecordProtection(state *dtlsstate.State13) error {
	if state == nil {
		return dtlserrors.ErrCipherSuiteNotSet
	}

	return initRecordProtectionFromTrafficSecrets(
		state,
		dtlsflight13.EpochApplication,
		dtlsstate.TrafficSecrets{
			Client: state.KeySchedule.ClientApplicationTrafficSecret0,
			Server: state.KeySchedule.ServerApplicationTrafficSecret0,
		},
		true,
	)
}

func activateApplicationRecordProtection(ctx context.Context, conn Conn, state *dtlsstate.State13) error {
	if err := InitApplicationRecordProtection(state); err != nil {
		return err
	}
	conn.SetLocalEpoch(dtlsflight13.EpochApplication)
	state.SetRemoteEpoch(dtlsflight13.EpochApplication)

	return conn.HandleQueuedPackets(ctx)
}

func initRecordProtectionFromTrafficSecrets( //nolint:cyclop
	state *dtlsstate.State13,
	epoch uint16,
	secrets dtlsstate.TrafficSecrets,
	allowReinitialize bool,
) error {
	tls13CipherSuite, err := recordProtectionCipherSuite(state)
	if err != nil {
		return err
	}
	if state.TrafficKeys == nil {
		state.TrafficKeys = &dtlsstate.TrafficKeyState{}
	}
	if !allowReinitialize {
		_, hasWrite := state.TrafficKeys.Write(epoch)
		_, hasRead := state.TrafficKeys.Read(epoch)
		if hasWrite && hasRead {
			return nil
		}
	}

	writeSecret, readSecret, err := directionalTrafficSecrets(secrets, state.IsClient)
	if err != nil {
		return err
	}
	writeTrafficSecret, err := dtlsciphersuite.NewTrafficSecret(writeSecret)
	if err != nil {
		return err
	}
	writeProtection, err := tls13CipherSuite.NewTrafficProtection(writeTrafficSecret)
	if err != nil {
		return err
	}
	if writeProtection == nil {
		return dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	readTrafficSecret, err := dtlsciphersuite.NewTrafficSecret(readSecret)
	if err != nil {
		return err
	}
	readProtection, err := tls13CipherSuite.NewTrafficProtection(readTrafficSecret)
	if err != nil {
		return err
	}
	if readProtection == nil {
		return dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	state.TrafficKeys.Install(
		&dtlsstate.TrafficGeneration{
			Epoch:      epoch,
			Generation: 0,
			Secret:     writeSecret,
			Protection: writeProtection,
		},
		&dtlsstate.TrafficGeneration{
			Epoch:      epoch,
			Generation: 0,
			Secret:     readSecret,
			Protection: readProtection,
		},
	)

	return nil
}

func recordProtectionCipherSuite(state *dtlsstate.State13) (cryptosuite.TrafficSuite, error) {
	if state == nil || state.CipherSuite == nil {
		return nil, dtlserrors.ErrCipherSuiteNotSet
	}

	tls13CipherSuite, ok := state.CipherSuite.(cryptosuite.TrafficSuite)
	if !ok {
		return nil, dtlserrors.ErrInvalidCipherSuite
	}

	return tls13CipherSuite, nil
}

func directionalTrafficSecrets(
	secrets dtlsstate.TrafficSecrets,
	isClient bool,
) (write, read []byte, err error) {
	if len(secrets.Client) == 0 || len(secrets.Server) == 0 {
		return nil, nil, dtlserrors.ErrCipherSuiteRecordProtectionNotImplemented
	}
	if isClient {
		return secrets.Client, secrets.Server, nil
	}

	return secrets.Server, secrets.Client, nil
}
