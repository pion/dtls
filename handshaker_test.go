package dtls

import (
	"context"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/transport/test"
)

const nonZeroRetransmitInterval = 100 * time.Millisecond

func TestHandshaker(t *testing.T) {
	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logging.NewDefaultLoggerFactory()
	logger := loggerFactory.NewLogger("dtls")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cipherSuites, err := parseCipherSuites(nil, true, false)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatal(err)
	}

	ca, cb := flightTestPipe(ctx)
	ca.state.isClient = true

	var wg sync.WaitGroup
	wg.Add(2)

	ctxCliFinished, cancelCli := context.WithCancel(ctx)
	ctxSrvFinished, cancelSrv := context.WithCancel(ctx)
	go func() {
		defer wg.Done()
		cfg := &handshakeConfig{
			localCipherSuites:     cipherSuites,
			localCertificates:     []tls.Certificate{clientCert},
			localSignatureSchemes: defaultSignatureSchemes(),
			insecureSkipVerify:    true,
			log:                   logger,
			onFlightState: func(f flightVal, s handshakeState) {
				if s == handshakeFinished {
					cancelCli()
				}
			},
			retransmitInterval: nonZeroRetransmitInterval,
		}

		fsm := newHandshakeFSM(&ca.state, ca.handshakeCache, cfg, flight1)
		switch err := fsm.Run(ctx, ca, handshakePreparing); err {
		case context.Canceled:
		case context.DeadlineExceeded:
			t.Error("Timeout")
		default:
			t.Error(err)
		}
	}()

	go func() {
		defer wg.Done()
		cfg := &handshakeConfig{
			localCipherSuites:     cipherSuites,
			localCertificates:     []tls.Certificate{clientCert},
			localSignatureSchemes: defaultSignatureSchemes(),
			insecureSkipVerify:    true,
			log:                   logger,
			onFlightState: func(f flightVal, s handshakeState) {
				if s == handshakeFinished {
					cancelSrv()
				}
			},
		}

		fsm := newHandshakeFSM(&cb.state, cb.handshakeCache, cfg, flight0)
		switch err := fsm.Run(ctx, cb, handshakePreparing); err {
		case context.Canceled:
		case context.DeadlineExceeded:
			t.Error("Timeout")
		default:
			t.Error(err)
		}
	}()

	<-ctxCliFinished.Done()
	<-ctxSrvFinished.Done()

	cancel()
	wg.Wait()
}

func flightTestPipe(ctx context.Context) (*flightTestConn, *flightTestConn) {
	ca := newHandshakeCache()
	cb := newHandshakeCache()
	chA := make(chan chan struct{})
	chB := make(chan chan struct{})
	return &flightTestConn{
			handshakeCache: ca,
			otherEndCache:  cb,
			recv:           chA,
			otherEndRecv:   chB,
			done:           ctx.Done(),
		}, &flightTestConn{
			handshakeCache: cb,
			otherEndCache:  ca,
			recv:           chB,
			otherEndRecv:   chA,
			done:           ctx.Done(),
		}
}

type flightTestConn struct {
	state          State
	handshakeCache *handshakeCache
	recv           chan chan struct{}
	done           <-chan struct{}
	epoch          uint16

	otherEndCache *handshakeCache
	otherEndRecv  chan chan struct{}
}

func (c *flightTestConn) recvHandshake() <-chan chan struct{} {
	return c.recv
}

func (c *flightTestConn) setLocalEpoch(epoch uint16) {
	c.epoch = epoch
}

func (c *flightTestConn) notify(ctx context.Context, level alertLevel, desc alertDescription) error {
	return nil
}

func (c *flightTestConn) writePackets(ctx context.Context, pkts []*packet) error {
	for _, p := range pkts {
		if h, ok := p.record.content.(*handshake); ok {
			handshakeRaw, err := p.record.Marshal()
			if err != nil {
				return err
			}

			c.handshakeCache.push(handshakeRaw[recordLayerHeaderSize:], p.record.recordLayerHeader.epoch, h.handshakeHeader.messageSequence, h.handshakeHeader.handshakeType, c.state.isClient)

			content, err := h.handshakeMessage.Marshal()
			if err != nil {
				return err
			}
			h.handshakeHeader.length = uint32(len(content))
			h.handshakeHeader.fragmentLength = uint32(len(content))
			hdr, err := h.handshakeHeader.Marshal()
			if err != nil {
				return err
			}
			c.otherEndCache.push(
				append(hdr, content...), p.record.recordLayerHeader.epoch, h.handshakeHeader.messageSequence, h.handshakeHeader.handshakeType, c.state.isClient)
		}
	}
	go func() {
		select {
		case c.otherEndRecv <- make(chan struct{}):
		case <-c.done:
		}
	}()

	// Avoid deadlock on JS/WASM environment due to context switch problem.
	time.Sleep(10 * time.Millisecond)

	return nil
}

func (c *flightTestConn) handleQueuedPackets(ctx context.Context) error {
	return nil
}
