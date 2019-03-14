package e2e

import (
	"testing"
	"time"

	"github.com/pions/dtls"
	transportTest "github.com/pions/transport/test"
)

const lossyTestTimeout = 30 * time.Second

/*
  DTLS Client/Server over a lossy transport, just asserts it can handle at increasing increments
*/
func TestPionE2ELossy(t *testing.T) {
	serverCert, serverKey, err := dtls.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		LossChance int
	}{
		{
			LossChance: 0,
		},
		{
			LossChance: 10,
		},
		{
			LossChance: 25,
		},
		{
			LossChance: 50,
		},
		{
			LossChance: 75,
		},
	} {
		serverDone := make(chan interface{})
		clientDone := make(chan interface{})
		br := transportTest.NewBridge()
		br.SetLossChance(test.LossChance)

		go func() {
			dtls.Client(br.GetConn0(), &dtls.Config{})
			close(clientDone)
		}()

		go func() {
			dtls.Server(br.GetConn1(), &dtls.Config{
				Certificate: serverCert,
				PrivateKey:  serverKey,
			})
			close(serverDone)
		}()

		testTimer := time.NewTimer(lossyTestTimeout)
		var serverComplete, clientComplete bool
		for {
			if serverComplete && clientComplete {
				break
			}

			br.Process()
			select {
			case <-serverDone:
				serverComplete = true
			case <-clientDone:
				clientComplete = true
			case <-testTimer.C:
				t.Fatalf("Test expired: clientComplete(%t) serverComplete(%t) LossChance(%d)", clientComplete, serverComplete, test.LossChance)
			default:
			}
		}
	}

}
