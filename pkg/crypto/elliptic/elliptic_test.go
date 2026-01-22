// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package elliptic

import (
	crand "crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestString(t *testing.T) {
	tests := []struct {
		in  Curve
		out string
	}{
		{X25519, "X25519"},
		{P256, "P-256"},
		{P384, "P-384"},
		{0, "0x0"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.out, func(t *testing.T) {
			assert.Equal(t, tt.in.String(), tt.out)
		})
	}
}

func TestGenerateKeypair_InvalidCurve(t *testing.T) {
	var invalid Curve = 0 // not a supported curve
	_, err := GenerateKeypair(invalid)
	assert.ErrorIs(t, err, errInvalidNamedCurve)
}

// create a fake reader that is guaranteed to fail to trigger a failure in generate keypair.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) {
	return 0, errors.ErrUnsupported // any error is fine here.
}

func TestGenerateKeypair_RandFailure(t *testing.T) {
	// replace crypto/rand.Reader to force ecdh.GenerateKey to fail.
	orig := crand.Reader
	crand.Reader = failingReader{}
	defer func() { crand.Reader = orig }()

	_, err := GenerateKeypair(P256)
	assert.Error(t, err)
}

func TestToECDH_InvalidCurve(t *testing.T) {
	var invalid Curve = 0xFFFF
	_, err := invalid.toECDH()
	assert.ErrorIs(t, err, errInvalidNamedCurve)
}
