// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	dtlserrors "github.com/pion/dtls/v3/internal/errors"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
)

// ErrConnClosed indicates that the connection is closed.
var ErrConnClosed = dtlserrors.ErrConnClosed //nolint:gochecknoglobals

// ErrStateSerializationUnsupported indicates that the negotiated DTLS version
// cannot be represented by the public DTLS 1.2-shaped State snapshot.
var ErrStateSerializationUnsupported = errors.New("dtls: state serialization unsupported for this protocol version") //nolint:gochecknoglobals,lll

// errInvalidCipherSuite indicates an attempt at using an unsupported cipher suite.
type invalidCipherSuiteError struct {
	id CipherSuiteID
}

func (e *invalidCipherSuiteError) Error() string {
	return fmt.Sprintf("CipherSuite with id(%d) is not valid", e.id)
}

func (e *invalidCipherSuiteError) Is(err error) bool {
	var other *invalidCipherSuiteError
	if errors.As(err, &other) {
		return e.id == other.id
	}

	return false
}

// errAlert wraps DTLS alert notification as an error.
type alertError struct {
	*alert.Alert
}

func (e *alertError) Error() string {
	return fmt.Sprintf("alert: %s", e.Alert.String())
}

func (e *alertError) IsFatalOrCloseNotify() bool {
	return e.Level == alert.Fatal || e.Description == alert.CloseNotify
}

func (e *alertError) Is(err error) bool {
	var other *alertError
	if errors.As(err, &other) {
		return e.Level == other.Level && e.Description == other.Description
	}

	return false
}

// netError translates an error from underlying Conn to corresponding net.Error.
func netError(err error) error {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Return io.EOF and context errors as is.
		return err
	}

	var (
		opError *net.OpError
		se      *os.SyscallError
	)

	if errors.As(err, &opError) { //nolint:nestif
		if errors.As(opError, &se) {
			if isOpErrorTemporary(se) {
				return temporaryNetworkError{err: err}
			}
		}
	}

	return err
}

type temporaryNetworkError struct {
	err error
}

func (e temporaryNetworkError) Error() string { return e.err.Error() }

func (e temporaryNetworkError) Unwrap() error { return e.err }

func (e temporaryNetworkError) Timeout() bool {
	var netErr net.Error
	if errors.As(e.err, &netErr) {
		return netErr.Timeout()
	}

	return false
}

func (temporaryNetworkError) Temporary() bool {
	return true
}
