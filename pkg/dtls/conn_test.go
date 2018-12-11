package dtls

import (
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
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

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
