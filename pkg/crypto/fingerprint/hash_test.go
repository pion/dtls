package fingerprint

import (
	"crypto"
	"testing"
)

func TestHashFromString(t *testing.T) {
	t.Run("InvalidHashAlgorithm", func(t *testing.T) {
		_, err := HashFromString("invalid-hash-algorithm")
		if err != errInvalidHashAlgorithm {
			t.Errorf("Expected error '%v' for invalid hash name, got '%v'", errInvalidHashAlgorithm, err)
		}
	})
	t.Run("ValidHashAlgorithm", func(t *testing.T) {
		h, err := HashFromString("sha-512")
		if err != nil {
			t.Fatalf("Unexpected error for valid hash name, got '%v'", err)
		}
		if h != crypto.SHA512 {
			t.Errorf("Expected hash ID of %d, got %d", int(crypto.SHA512), int(h))
		}
	})
}
