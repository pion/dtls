package dtls

import (
	"testing"

	"github.com/pion/dtls/v2/pkg/crypto/fingerprint"
)

func TestHashAlgorithm_StringRoundtrip(t *testing.T) {
	for algo := range hashAlgorithms() {
		if algo == hashAlgorithmEd25519 {
			// Ed25519 does hashing and signing in one time.
			continue
		}
		str := algo.String()
		hash1 := algo.cryptoHash()
		hash2, err := fingerprint.HashFromString(str)
		if err != nil {
			t.Fatalf("fingerprint.HashFromString failed: %v", err)
		}
		if hash1 != hash2 {
			t.Errorf("Hash algorithm mismatch, input: %d, after roundtrip: %d", int(hash1), int(hash2))
		}
	}
}
