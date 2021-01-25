package dtls

import (
	"context"
	"testing"
	"time"

	"github.com/pion/dtls/v2/internal/ciphersuite"
	"github.com/pion/dtls/v2/internal/net/dpipe"
	"github.com/pion/transport/test"
)

func TestCipherSuiteName(t *testing.T) {
	testCases := []struct {
		suite    CipherSuiteID
		expected string
	}{
		{TLS_ECDHE_ECDSA_WITH_AES_128_CCM, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"},
		{CipherSuiteID(0x0000), "0x0000"},
	}

	for _, testCase := range testCases {
		res := CipherSuiteName(testCase.suite)
		if res != testCase.expected {
			t.Fatalf("Expected: %s, got %s", testCase.expected, res)
		}
	}
}

func TestAllCipherSuites(t *testing.T) {
	actual := len(allCipherSuites())
	if actual == 0 {
		t.Fatal()
	}
}

// CustomCipher that is just used to test CustomerCiphers and Anonymous Authentication
type testCustomCipherSuite struct {
	ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256
}

func (t *testCustomCipherSuite) ID() CipherSuiteID {
	return 0xFFFF
}

// Assert that two connections that pass in a CipherSuite with a CustomID works
func TestCustomCipherSuite(t *testing.T) {
	type result struct {
		c   *Conn
		err error
	}

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	t.Run("Custom ID", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ca, cb := dpipe.Pipe()
		c := make(chan result)

		go func() {
			client, err := testClient(ctx, ca, &Config{
				CipherSuites:       []CipherSuiteID{},
				CustomCipherSuites: func() []CipherSuite { return []CipherSuite{&testCustomCipherSuite{}} },
			}, true)
			c <- result{client, err}
		}()

		server, err := testServer(ctx, cb, &Config{
			CipherSuites:       []CipherSuiteID{},
			CustomCipherSuites: func() []CipherSuite { return []CipherSuite{&testCustomCipherSuite{}} },
		}, true)

		if err != nil {
			t.Error(err)
		} else {
			_ = server.Close()
		}

		if res := <-c; res.err != nil {
			t.Error(res.err)
		} else {
			_ = res.c.Close()
		}
	})
}
