// +build go1.13,!js

package e2e

import (
	"crypto/rand"
	"crypto/tls"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/transport/test"
)

// ED25519 is not supported in Go 1.12 crypto/x509.
// Once Go 1.12 is deprecated, move this test to e2e_test.go.

func TestPionE2ESimpleED25519(t *testing.T) {
	lim := test.TimeOut(time.Second * 30)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	serverPort := randomPort(t)

	for _, cipherSuite := range []dtls.CipherSuiteID{
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	} {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := selfsign.SelfSign(key)
		if err != nil {
			t.Fatal(err)
		}

		cfg := &dtls.Config{
			Certificates:       []tls.Certificate{cert},
			CipherSuites:       []dtls.CipherSuiteID{cipherSuite},
			InsecureSkipVerify: true,
			ConnectTimeout:     dtls.ConnectTimeoutOption(5 * time.Second),
		}
		assertE2ECommunication(cfg, cfg, serverPort, t)
	}
}
