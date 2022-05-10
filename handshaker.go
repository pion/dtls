package dtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pion/dtls/v2/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v2/pkg/protocol/alert"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"github.com/pion/logging"
)

// [RFC6347 Section-4.2.4]
//                      +-----------+
//                +---> | PREPARING | <--------------------+
//                |     +-----------+                      |
//                |           |                            |
//                |           | Buffer next flight         |
//                |           |                            |
//                |          \|/                           |
//                |     +-----------+                      |
//                |     |  SENDING  |<------------------+  | Send
//                |     +-----------+                   |  | HelloRequest
//        Receive |           |                         |  |
//           next |           | Send flight             |  | or
//         flight |  +--------+                         |  |
//                |  |        | Set retransmit timer    |  | Receive
//                |  |       \|/                        |  | HelloRequest
//                |  |  +-----------+                   |  | Send
//                +--)--|  WAITING  |-------------------+  | ClientHello
//                |  |  +-----------+   Timer expires   |  |
//                |  |         |                        |  |
//                |  |         +------------------------+  |
//        Receive |  | Send           Read retransmit      |
//           last |  | last                                |
//         flight |  | flight                              |
//                |  |                                     |
//               \|/\|/                                    |
//            +-----------+                                |
//            | FINISHED  | -------------------------------+
//            +-----------+
//                 |  /|\
//                 |   |
//                 +---+
//              Read retransmit
//           Retransmit last flight

type HandshakeState uint8

const (
	HandshakeErrored HandshakeState = iota
	HandshakePreparing
	HandshakeSending
	HandshakeWaiting
	HandshakeFinished
)

func (s HandshakeState) String() string {
	switch s {
	case HandshakeErrored:
		return "Errored"
	case HandshakePreparing:
		return "Preparing"
	case HandshakeSending:
		return "Sending"
	case HandshakeWaiting:
		return "Waiting"
	case HandshakeFinished:
		return "Finished"
	default:
		return "Unknown"
	}
}

type handshakeFSM struct {
	currentFlight FlightVal
	flights       []*packet
	retransmit    bool
	state         *State
	cache         *handshakeCache
	cfg           *handshakeConfig
	closed        chan struct{}
}

type handshakeConfig struct {
	localPSKCallback            PSKCallback
	localPSKIdentityHint        []byte
	localHandshakeCallback      HandshakeCallback
	localCipherSuites           []CipherSuite             // Available CipherSuites
	localSignatureSchemes       []signaturehash.Algorithm // Available signature schemes
	extendedMasterSecret        ExtendedMasterSecretType  // Policy for the Extended Master Support extension
	localSRTPProtectionProfiles []SRTPProtectionProfile   // Available SRTPProtectionProfiles, if empty no SRTP support
	serverName                  string
	supportedProtocols          []string
	clientAuth                  ClientAuthType // If we are a client should we request a client certificate
	localCertificates           []tls.Certificate
	nameToCertificate           map[string]*tls.Certificate
	insecureSkipVerify          bool
	verifyPeerCertificate       func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	sessionStore                SessionStore
	rootCAs                     *x509.CertPool
	clientCAs                   *x509.CertPool
	retransmitInterval          time.Duration
	customCipherSuites          func() []CipherSuite

	onFlightState func(FlightVal, HandshakeState)
	log           logging.LeveledLogger
	keyLogWriter  io.Writer

	initialEpoch uint16

	mu sync.Mutex
}

type flightConn interface {
	notify(ctx context.Context, level alert.Level, desc alert.Description) error
	writePackets(context.Context, []*packet) error
	recvHandshake() <-chan chan struct{}
	setLocalEpoch(epoch uint16)
	handleQueuedPackets(context.Context) error
	sessionKey() []byte
}

func (c *handshakeConfig) writeKeyLog(label string, clientRandom, secret []byte) {
	if c.keyLogWriter == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.keyLogWriter.Write([]byte(fmt.Sprintf("%s %x %x\n", label, clientRandom, secret)))
	if err != nil {
		c.log.Debugf("failed to write key log file: %s", err)
	}
}

func srvCliStr(isClient bool) string {
	if isClient {
		return "client"
	}
	return "server"
}

func newHandshakeFSM(
	s *State, cache *handshakeCache, cfg *handshakeConfig,
	initialFlight FlightVal,
) *handshakeFSM {
	return &handshakeFSM{
		currentFlight: initialFlight,
		state:         s,
		cache:         cache,
		cfg:           cfg,
		closed:        make(chan struct{}),
	}
}

func (s *handshakeFSM) Run(ctx context.Context, c flightConn, initialState HandshakeState) error {
	state := initialState
	defer func() {
		close(s.closed)
	}()
	for {
		s.cfg.log.Tracef("[handshake:%s] %s: %s", srvCliStr(s.state.isClient), s.currentFlight.String(), state.String())
		if s.cfg.onFlightState != nil {
			s.cfg.onFlightState(s.currentFlight, state)
		}
		var err error
		switch state {
		case HandshakePreparing:
			state, err = s.prepare(ctx, c)
		case HandshakeSending:
			state, err = s.send(ctx, c)
		case HandshakeWaiting:
			state, err = s.wait(ctx, c)
		case HandshakeFinished:
			state, err = s.finish(ctx, c)
		default:
			return errInvalidFSMTransition
		}
		if err != nil {
			return err
		}
	}
}

func (s *handshakeFSM) Done() <-chan struct{} {
	return s.closed
}

func (s *handshakeFSM) prepare(ctx context.Context, c flightConn) (HandshakeState, error) {
	s.flights = nil
	// Prepare flights
	var (
		a    *alert.Alert
		err  error
		pkts []*packet
	)
	gen, retransmit, errFlight := s.currentFlight.getFlightGenerator()
	if errFlight != nil {
		err = errFlight
		a = &alert.Alert{Level: alert.Fatal, Description: alert.InternalError}
	} else {
		pkts, a, err = gen(c, s.state, s.cache, s.cfg)
		s.retransmit = retransmit
	}
	if a != nil {
		if alertErr := c.notify(ctx, a.Level, a.Description); alertErr != nil {
			if err != nil {
				err = alertErr
			}
		}
	}
	if err != nil {
		return HandshakeErrored, err
	}

	s.flights = pkts
	epoch := s.cfg.initialEpoch
	nextEpoch := epoch
	for _, p := range s.flights {
		p.record.Header.Epoch += epoch
		if p.record.Header.Epoch > nextEpoch {
			nextEpoch = p.record.Header.Epoch
		}
		if h, ok := p.record.Content.(*handshake.Handshake); ok {
			h.Header.MessageSequence = uint16(s.state.handshakeSendSequence)
			s.state.handshakeSendSequence++
		}
	}
	if epoch != nextEpoch {
		s.cfg.log.Tracef("[handshake:%s] -> changeCipherSpec (epoch: %d)", srvCliStr(s.state.isClient), nextEpoch)
		c.setLocalEpoch(nextEpoch)
	}
	return HandshakeSending, nil
}

func (s *handshakeFSM) send(ctx context.Context, c flightConn) (HandshakeState, error) {
	// Send flights
	if err := c.writePackets(ctx, s.flights); err != nil {
		return HandshakeErrored, err
	}

	if s.currentFlight.isLastSendFlight() {
		return HandshakeFinished, nil
	}
	return HandshakeWaiting, nil
}

func (s *handshakeFSM) wait(ctx context.Context, c flightConn) (HandshakeState, error) { //nolint:gocognit
	parse, errFlight := s.currentFlight.getFlightParser()
	if errFlight != nil {
		if alertErr := c.notify(ctx, alert.Fatal, alert.InternalError); alertErr != nil {
			if errFlight != nil {
				return HandshakeErrored, alertErr
			}
		}
		return HandshakeErrored, errFlight
	}

	retransmitTimer := time.NewTimer(s.cfg.retransmitInterval)
	for {
		select {
		case done := <-c.recvHandshake():
			nextFlight, alert, err := parse(ctx, c, s.state, s.cache, s.cfg)
			close(done)
			if alert != nil {
				if alertErr := c.notify(ctx, alert.Level, alert.Description); alertErr != nil {
					if err != nil {
						err = alertErr
					}
				}
			}
			if err != nil {
				return HandshakeErrored, err
			}
			if nextFlight == 0 {
				break
			}
			s.cfg.log.Tracef("[handshake:%s] %s -> %s", srvCliStr(s.state.isClient), s.currentFlight.String(), nextFlight.String())
			if nextFlight.isLastRecvFlight() && s.currentFlight == nextFlight {
				return HandshakeFinished, nil
			}
			s.currentFlight = nextFlight
			return HandshakePreparing, nil

		case <-retransmitTimer.C:
			if !s.retransmit {
				return HandshakeWaiting, nil
			}
			return HandshakeSending, nil
		case <-ctx.Done():
			return HandshakeErrored, ctx.Err()
		}
	}
}

func (s *handshakeFSM) finish(ctx context.Context, c flightConn) (HandshakeState, error) {
	parse, errFlight := s.currentFlight.getFlightParser()
	if errFlight != nil {
		if alertErr := c.notify(ctx, alert.Fatal, alert.InternalError); alertErr != nil {
			if errFlight != nil {
				return HandshakeErrored, alertErr
			}
		}
		return HandshakeErrored, errFlight
	}

	retransmitTimer := time.NewTimer(s.cfg.retransmitInterval)
	select {
	case done := <-c.recvHandshake():
		nextFlight, alert, err := parse(ctx, c, s.state, s.cache, s.cfg)
		close(done)
		if alert != nil {
			if alertErr := c.notify(ctx, alert.Level, alert.Description); alertErr != nil {
				if err != nil {
					err = alertErr
				}
			}
		}
		if err != nil {
			return HandshakeErrored, err
		}
		if nextFlight == 0 {
			break
		}
		if nextFlight.isLastRecvFlight() && s.currentFlight == nextFlight {
			return HandshakeFinished, nil
		}
		<-retransmitTimer.C
		// Retransmit last flight
		return HandshakeSending, nil

	case <-ctx.Done():
		return HandshakeErrored, ctx.Err()
	}
	return HandshakeFinished, nil
}
