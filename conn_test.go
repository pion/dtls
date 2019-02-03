package dtls

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/pions/transport/test"
)

// Seems to strict for out implementation at this point
// func TestNetTest(t *testing.T) {
// 	lim := test.TimeOut(time.Minute*1 + time.Second*10)
// 	defer lim.Stop()
//
// 	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
// 		c1, c2, err = pipeMemory()
// 		if err != nil {
// 			return nil, nil, nil, err
// 		}
// 		stop = func() {
// 			c1.Close()
// 			c2.Close()
// 		}
// 		return
// 	})
// }

func TestStressDuplex(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	// Run the test
	stressDuplex(t)
}

func stressDuplex(t *testing.T) {
	ca, cb, err := pipeMemory()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = ca.Close()
		if err != nil {
			t.Fatal(err)
		}
		err = cb.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	opt := test.Options{
		MsgSize:  2048,
		MsgCount: 100,
	}

	err = test.StressDuplex(ca, cb, opt)
	if err != nil {
		t.Fatal(err)
	}
}

func pipeMemory() (*Conn, *Conn, error) {
	// In memory pipe
	ca, cb := net.Pipe()

	type result struct {
		c   *Conn
		err error
	}

	c := make(chan result)

	// Setup client
	go func() {
		client, err := testClient(ca)
		c <- result{client, err}
	}()

	// Setup server
	server, err := testServer(cb)
	if err != nil {
		return nil, nil, err
	}

	// Receive client
	res := <-c
	if res.err != nil {
		return nil, nil, res.err
	}

	return res.c, server, nil
}

func testClient(c net.Conn) (*Conn, error) {
	clientCert, clientKey, err := GenerateSelfSigned()
	if err != nil {
		return nil, err
	}

	client, err := Client(c, &Config{clientCert, clientKey})
	if err != nil {
		return nil, err
	}

	return client, nil
}

func testServer(c net.Conn) (*Conn, error) {
	serverCert, serverKey, err := GenerateSelfSigned()
	if err != nil {
		return nil, err
	}

	server, err := Server(c, &Config{serverCert, serverKey})
	if err != nil {
		return nil, err
	}

	return server, nil
}

func TestExportKeyingMaterial(t *testing.T) {
	var rand [28]byte
	exportLabel := "EXTRACTOR-dtls_srtp"

	expectedServerKey := []byte{0x61, 0x09, 0x9d, 0x7d, 0xcb, 0x08, 0x52, 0x2c, 0xe7, 0x7b}
	expectedClientKey := []byte{0x87, 0xf0, 0x40, 0x02, 0xf6, 0x1c, 0xf1, 0xfe, 0x8c, 0x77}

	c := &Conn{
		localRandom:  handshakeRandom{time.Unix(500, 0), rand},
		remoteRandom: handshakeRandom{time.Unix(1000, 0), rand},
		cipherSuite:  &cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{},
	}
	c.setLocalEpoch(0)

	_, err := c.ExportKeyingMaterial(exportLabel, nil, 0)
	if err != errHandshakeInProgress {
		t.Errorf("ExportKeyingMaterial when epoch == 0: expected '%s' actual '%s'", errHandshakeInProgress, err)
	}

	c.setLocalEpoch(1)
	_, err = c.ExportKeyingMaterial(exportLabel, []byte{0x00}, 0)
	if err != errContextUnsupported {
		t.Errorf("ExportKeyingMaterial with context: expected '%s' actual '%s'", errContextUnsupported, err)
	}

	for k := range invalidKeyingLabels {
		_, err = c.ExportKeyingMaterial(k, nil, 0)
		if err != errReservedExportKeyingMaterial {
			t.Errorf("ExportKeyingMaterial reserved label: expected '%s' actual '%s'", errReservedExportKeyingMaterial, err)
		}
	}

	keyingMaterial, err := c.ExportKeyingMaterial(exportLabel, nil, 10)
	if err != nil {
		t.Errorf("ExportKeyingMaterial as server: unexpected error '%s'", err)
	} else if !bytes.Equal(keyingMaterial, expectedServerKey) {
		t.Errorf("ExportKeyingMaterial client export: expected (% 02x) actual (% 02x)", expectedServerKey, keyingMaterial)
	}

	c.isClient = true
	keyingMaterial, err = c.ExportKeyingMaterial(exportLabel, nil, 10)
	if err != nil {
		t.Errorf("ExportKeyingMaterial as server: unexpected error '%s'", err)
	} else if !bytes.Equal(keyingMaterial, expectedClientKey) {
		t.Errorf("ExportKeyingMaterial client export: expected (% 02x) actual (% 02x)", expectedClientKey, keyingMaterial)
	}
}
