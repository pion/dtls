// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

var errExample = errors.New("an example error")

func TestErrorUnwrap(t *testing.T) {
	cases := []struct {
		err          error
		errUnwrapped []error
	}{
		{
			&FatalError{Err: errExample},
			[]error{errExample},
		},
		{
			&TemporaryError{Err: errExample},
			[]error{errExample},
		},
		{
			&InternalError{Err: errExample},
			[]error{errExample},
		},
		{
			&TimeoutError{Err: errExample},
			[]error{errExample},
		},
		{
			&HandshakeError{Err: errExample},
			[]error{errExample},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(fmt.Sprintf("%T", c.err), func(t *testing.T) {
			err := c.err
			for _, unwrapped := range c.errUnwrapped {
				assert.ErrorIs(t, errors.Unwrap(err), unwrapped)
			}
		})
	}
}

func TestErrorNetError(t *testing.T) {
	cases := []struct {
		err                error
		str                string
		timeout, temporary bool
	}{
		{&FatalError{Err: errExample}, "dtls fatal: an example error", false, false},
		{&TemporaryError{Err: errExample}, "dtls temporary: an example error", false, true},
		{&InternalError{Err: errExample}, "dtls internal: an example error", false, false},
		{&TimeoutError{Err: errExample}, "dtls timeout: an example error", true, true},
		{&HandshakeError{Err: errExample}, "handshake error: an example error", false, false},
		{&HandshakeError{Err: &TimeoutError{Err: errExample}}, "handshake error: dtls timeout: an example error", true, true},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(fmt.Sprintf("%T", testCase.err), func(t *testing.T) {
			var ne net.Error
			assert.ErrorAs(t, testCase.err, &ne)
			assert.Equal(t, testCase.timeout, ne.Timeout())
			assert.Equal(t, testCase.temporary, ne.Temporary()) //nolint:staticcheck
			assert.Equal(t, testCase.str, ne.Error())
		})
	}
}
