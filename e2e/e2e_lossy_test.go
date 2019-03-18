package e2e

import (
	"math/rand"
	"testing"
	"time"

	"github.com/pions/dtls"
	transportTest "github.com/pions/transport/test"
)

const (
	flightInterval   = time.Millisecond * 100
	lossyTestTimeout = 30 * time.Second
)

/*
  DTLS Client/Server over a lossy transport, just asserts it can handle at increasing increments
*/
func TestPionE2ELossy(t *testing.T) {
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
	} {
		rand.Seed(time.Now().UTC().UnixNano())
		chosenLoss := rand.Intn(9) + test.LossChanceRange
		serverDone := make(chan error)
		clientDone := make(chan error)
		br := transportTest.NewBridge()
		if err := br.SetLossChance(chosenLoss); err != nil {
			t.Fatal(err)
		}

		go func() {
			cfg := &dtls.Config{
				FlightInterval: flightInterval,
			}
			if test.DoClientAuth {
				cfg.Certificate = clientCert
				cfg.PrivateKey = clientKey
			}

			if _, err := dtls.Client(br.GetConn0(), cfg); err != nil {
				clientDone <- err
			} else {
				close(clientDone)
			}
		}()

		go func() {
			cfg := &dtls.Config{
				Certificate:    serverCert,
				PrivateKey:     serverKey,
				FlightInterval: flightInterval,
			}
			if test.DoClientAuth {
				cfg.ClientAuth = dtls.RequireAnyClientCert

			}

			if _, err := dtls.Server(br.GetConn1(), cfg); err != nil {
				serverDone <- err
			} else {
				close(serverDone)
			}
		}()

		testTimer := time.NewTimer(lossyTestTimeout)
		var serverComplete, clientComplete bool
		for {
			if serverComplete && clientComplete {
				break
			}

			br.Tick()
			select {
			case err, ok := <-serverDone:
				if ok {
					t.Fatalf("Fail, serverError: clientComplete(%t) serverComplete(%t) LossChance(%d) error(%v)", clientComplete, serverComplete, chosenLoss, err)
				}

				serverComplete = true
			case err, ok := <-clientDone:
				if ok {
					t.Fatalf("Fail, clientError: clientComplete(%t) serverComplete(%t) LossChance(%d) error(%v)", clientComplete, serverComplete, chosenLoss, err)
				}

				clientComplete = true
			case <-testTimer.C:
				t.Fatalf("Test expired: clientComplete(%t) serverComplete(%t) LossChance(%d)", clientComplete, serverComplete, chosenLoss)
			default:
			}
		}
	}

}
