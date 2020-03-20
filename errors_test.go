package dtls

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"golang.org/x/xerrors"
)

func TestErrorUnwrap(t *testing.T) {
	errExample := errors.New("an example error")

	cases := []struct {
		err          error
		errUnwrapped []error
	}{
		{
			&FatalError{errExample},
			[]error{errExample},
		},
		{
			&TemporaryError{errExample},
			[]error{errExample},
		},
		{
			&InternalError{errExample},
			[]error{errExample},
		},
		{
			&TimeoutError{errExample},
			[]error{errExample},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(fmt.Sprintf("%T", c.err), func(t *testing.T) {
			err := c.err
			for _, unwrapped := range c.errUnwrapped {
				e := xerrors.Unwrap(err)
				if e != unwrapped {
					t.Errorf("Unwrapped error is expected to be '%v', got '%v'", unwrapped, e)
				}
			}
		})
	}
}

func TestErrorNetError(t *testing.T) {
	errExample := errors.New("an example error")

	cases := []struct {
		err                error
		str                string
		timeout, temporary bool
	}{
		{&FatalError{errExample}, "dtls fatal: an example error", false, false},
		{&TemporaryError{errExample}, "dtls temporary: an example error", false, true},
		{&InternalError{errExample}, "dtls internal: an example error", false, false},
		{&TimeoutError{errExample}, "dtls timeout: an example error", true, true},
	}
	for _, c := range cases {
		c := c
		t.Run(fmt.Sprintf("%T", c.err), func(t *testing.T) {
			ne, ok := c.err.(net.Error)
			if !ok {
				t.Fatalf("%T doesn't implement net.Error", c.err)
			}
			if ne.Timeout() != c.timeout {
				t.Errorf("%T.Timeout() should be %v", c.err, c.timeout)
			}
			if ne.Temporary() != c.temporary {
				t.Errorf("%T.Temporary() should be %v", c.err, c.temporary)
			}
		})
	}
}
