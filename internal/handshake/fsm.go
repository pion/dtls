// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"context"
	"errors"
	"time"

	dtlsconfig "github.com/pion/dtls/v3/internal/config"
	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

type fsmStateHandler func(context.Context, Conn) (State, error)

// runHandshakeFSM drives the shared preparing/sending/waiting/finished loop.
func runHandshakeFSM(ctx context.Context, conn Conn, initialState State, closed chan struct{}, establishment *Establishment, trace func(State), prepare, send, wait, finish fsmStateHandler) error {
	state := initialState
	defer close(closed)

	for {
		trace(state)
		if state == StateFinished {
			establishment.mark()
		}

		var err error
		switch state {
		case StatePreparing:
			state, err = prepare(ctx, conn)
		case StateSending:
			state, err = send(ctx, conn)
		case StateWaiting:
			state, err = wait(ctx, conn)
		case StateFinished:
			state, err = finish(ctx, conn)
		default:
			return dtlserrors.ErrInvalidFSMTransition
		}
		if err != nil {
			return err
		}
	}
}

// notifyAlert sends a DTLS alert if present and prefers the original error.
func notifyAlert(ctx context.Context, conn Conn, dtlsAlert *alert.Alert, err error) error {
	if dtlsAlert == nil && err != nil {
		errors.As(err, &dtlsAlert)
	}
	if dtlsAlert == nil {
		return err
	}
	if alertErr := conn.Notify(ctx, dtlsAlert.Level, dtlsAlert.Description); alertErr != nil && err == nil {
		return alertErr
	}

	return err
}

func handleRetransmitTimeout(retransmit bool, retransmitInterval *time.Duration, cfg *dtlsconfig.HandshakeConfig) State {
	if !retransmit {
		return StateWaiting
	}

	// RFC 4347 4.2.4.1: retransmissions use exponential backoff, capped at
	// 60 seconds.
	if !cfg.DisableRetransmitBackoff {
		*retransmitInterval *= 2
	}
	if *retransmitInterval > time.Second*60 {
		*retransmitInterval = time.Second * 60
	}

	return StateSending
}

func handleWaitCancellation(retransmitInterval *time.Duration, cfg *dtlsconfig.HandshakeConfig, err error) (State, error) {
	*retransmitInterval = cfg.InitialRetransmitInterval

	return StateErrored, err
}
