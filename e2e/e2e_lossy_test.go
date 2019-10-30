package e2e

import (
	"math/rand"
	"testing"
	"time"

	"github.com/pion/dtls"
	transportTest "github.com/pion/transport/test"
)

const (
	flightInterval   = time.Millisecond * 100
	lossyTestTimeout = 30 * time.Second
)

/*
  DTLS Client/Server over a lossy transport, just asserts it can handle at increasing increments
*/
func TestPionE2ELossy(t *testing.T) {
	type runResult struct {
		dtlsConn *dtls.Conn
		err      error
	}

	serverCert, serverKey, err := dtls.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	clientCert, clientKey, err := dtls.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		LossChanceRange int
		DoClientAuth    bool
		CipherSuites    []dtls.CipherSuiteID
		MTU             int
	}{
		{
			LossChanceRange: 0,
		},
		{
			LossChanceRange: 10,
		},
		{
			LossChanceRange: 20,
		},
		{
			LossChanceRange: 50,
		},
		{
			LossChanceRange: 0,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 10,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 20,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 50,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 0,
			CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		},
		{
			LossChanceRange: 10,
			CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		},
		{
			LossChanceRange: 20,
			CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		},
		{
			LossChanceRange: 50,
			CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		},
		{
			LossChanceRange: 10,
			MTU:             100,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 20,
			MTU:             100,
			DoClientAuth:    true,
		},
		{
			LossChanceRange: 50,
			MTU:             100,
			DoClientAuth:    true,
		},
	} {
		rand.Seed(time.Now().UTC().UnixNano())
		chosenLoss := rand.Intn(9) + test.LossChanceRange
		serverDone := make(chan runResult)
		clientDone := make(chan runResult)
		br := transportTest.NewBridge()

		if err = br.SetLossChance(chosenLoss); err != nil {
			t.Fatal(err)
		}

		go func() {
			cfg := &dtls.Config{
				FlightInterval:     flightInterval,
				CipherSuites:       test.CipherSuites,
				InsecureSkipVerify: true,
				MTU:                test.MTU,
			}

			if test.DoClientAuth {
				cfg.Certificate = clientCert
				cfg.PrivateKey = clientKey
			}

			client, startupErr := dtls.Client(br.GetConn0(), cfg)
			clientDone <- runResult{client, startupErr}
		}()

		go func() {
			cfg := &dtls.Config{
				Certificate:    serverCert,
				PrivateKey:     serverKey,
				FlightInterval: flightInterval,
				MTU:            test.MTU,
			}

			if test.DoClientAuth {
				cfg.ClientAuth = dtls.RequireAnyClientCert
			}

			server, startupErr := dtls.Server(br.GetConn1(), cfg)
			serverDone <- runResult{server, startupErr}
		}()

		testTimer := time.NewTimer(lossyTestTimeout)
		var serverConn, clientConn *dtls.Conn
		for {
			if serverConn != nil && clientConn != nil {
				break
			}

			br.Tick()
			select {
			case serverResult := <-serverDone:
				if serverResult.err != nil {
					t.Fatalf("Fail, serverError: clientComplete(%t) serverComplete(%t) LossChance(%d) error(%v)", clientConn != nil, serverConn != nil, chosenLoss, serverResult.err)
				}

				serverConn = serverResult.dtlsConn
			case clientResult := <-clientDone:
				if clientResult.err != nil {
					t.Fatalf("Fail, clientError: clientComplete(%t) serverComplete(%t) LossChance(%d) error(%v)", clientConn != nil, serverConn != nil, chosenLoss, clientResult.err)
				}

				clientConn = clientResult.dtlsConn
			case <-testTimer.C:
				t.Fatalf("Test expired: clientComplete(%t) serverComplete(%t) LossChance(%d)", clientConn != nil, serverConn != nil, chosenLoss)
			default:
			}
		}

		if err = serverConn.Close(); err != nil {
			t.Fatal(err)
		}

		clientConn.Close() //nolint
	}
}
