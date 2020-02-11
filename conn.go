package dtls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v2/internal/closer"
	"github.com/pion/dtls/v2/internal/net/deadline"
	"github.com/pion/logging"
)

const (
	initialTickerInterval = time.Second
	cookieLength          = 20
	defaultNamedCurve     = namedCurveX25519
	inboundBufferSize     = 8192
)

var invalidKeyingLabels = map[string]bool{
	"client finished": true,
	"server finished": true,
	"master secret":   true,
	"key expansion":   true,
}

type handshakeMessageHandler func(*Conn) (*alert, error)
type flightHandler func(*Conn) (bool, *alert, error)

// Conn represents a DTLS connection
type Conn struct {
	lock           sync.RWMutex    // Internal lock (must not be public)
	nextConn       net.Conn        // Embedded Conn, typically a udpconn we read/write from
	fragmentBuffer *fragmentBuffer // out-of-order and missing fragment handling
	handshakeCache *handshakeCache // caching of handshake messages for verifyData generation
	decrypted      chan []byte     // Decrypted Application Data, pull by calling `Read`
	workerTicker   *time.Ticker

	state State // Internal state

	maximumTransmissionUnit int

	remoteRequestedCertificate bool // Did we get a CertificateRequest

	localSRTPProtectionProfiles []SRTPProtectionProfile // Available SRTPProtectionProfiles, if empty no SRTP support
	localCipherSuites           []cipherSuite           // Available CipherSuites, if empty use default list

	clientAuth           ClientAuthType           // If we are a client should we request a client certificate
	extendedMasterSecret ExtendedMasterSecretType // Policy for the Extended Master Support extension

	currFlight        *flight
	namedCurve        namedCurve
	localCertificates []tls.Certificate
	localKeypair      *namedCurveKeypair
	cookie            []byte

	localPSKCallback     PSKCallback
	localPSKIdentityHint []byte

	localCertificatesVerify   []byte // cache CertificateVerify
	localVerifyData           []byte // cached VerifyData
	localKeySignature         []byte // cached keySignature
	remoteCertificateVerified bool

	insecureSkipVerify    bool
	verifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	rootCAs               *x509.CertPool
	clientCAs             *x509.CertPool
	serverName            string

	handshakeMessageSequence       int
	handshakeMessageHandler        handshakeMessageHandler
	flightHandler                  flightHandler
	handshakeDoneSignal            *closer.Closer
	handshakeCompletedSuccessfully atomic.Value

	bufferedPackets []*packet

	connectionClosed *closer.Closer // Closed on connection close and unblock read
	handshakeErr     *atomicError   // Error if one occurred during handshake
	readErr          *atomicError   // Error if one occurred in inboundLoop

	readDeadline  *deadline.Deadline
	writeDeadline *deadline.Deadline

	log logging.LeveledLogger
}

func createConn(ctx context.Context, nextConn net.Conn, flightHandler flightHandler, handshakeMessageHandler handshakeMessageHandler, config *Config, isClient bool) (*Conn, error) {
	err := validateConfig(config)
	if err != nil {
		return nil, err
	}

	if nextConn == nil {
		return nil, errNilNextConn
	}

	cipherSuites, err := parseCipherSuites(config.CipherSuites, config.PSK == nil, config.PSK != nil)
	if err != nil {
		return nil, err
	}

	workerInterval := initialTickerInterval
	if config.FlightInterval != 0 {
		workerInterval = config.FlightInterval
	}

	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}

	logger := loggerFactory.NewLogger("dtls")

	mtu := config.MTU
	if mtu <= 0 {
		mtu = defaultMTU
	}

	handshakeDoneSignal := closer.NewCloser()
	connectionClosed := closer.NewCloser()

	c := &Conn{
		nextConn:                    nextConn,
		currFlight:                  newFlight(isClient, logger),
		fragmentBuffer:              newFragmentBuffer(),
		handshakeCache:              newHandshakeCache(),
		handshakeMessageHandler:     handshakeMessageHandler,
		flightHandler:               flightHandler,
		maximumTransmissionUnit:     mtu,
		localCertificates:           config.Certificates,
		clientAuth:                  config.ClientAuth,
		extendedMasterSecret:        config.ExtendedMasterSecret,
		insecureSkipVerify:          config.InsecureSkipVerify,
		verifyPeerCertificate:       config.VerifyPeerCertificate,
		rootCAs:                     config.RootCAs,
		clientCAs:                   config.ClientCAs,
		serverName:                  config.ServerName,
		localSRTPProtectionProfiles: config.SRTPProtectionProfiles,
		localCipherSuites:           cipherSuites,
		namedCurve:                  defaultNamedCurve,

		localPSKCallback:     config.PSK,
		localPSKIdentityHint: config.PSKIdentityHint,

		decrypted:           make(chan []byte),
		workerTicker:        time.NewTicker(workerInterval),
		handshakeDoneSignal: handshakeDoneSignal,
		connectionClosed:    connectionClosed,
		log:                 logger,
		handshakeErr:        &atomicError{},
		readErr:             &atomicError{},

		readDeadline:  deadline.New(),
		writeDeadline: deadline.New(),
	}

	// Use host from conn address when serverName is not provided
	if isClient && c.serverName == "" && nextConn.RemoteAddr() != nil {
		remoteAddr := nextConn.RemoteAddr().String()
		var host string
		host, _, err = net.SplitHostPort(remoteAddr)
		if err != nil {
			c.serverName = remoteAddr
		}
		c.serverName = host
	}

	var zeroEpoch uint16
	c.state.localEpoch.Store(zeroEpoch)
	c.state.remoteEpoch.Store(zeroEpoch)
	c.state.isClient = isClient

	if err = c.state.localRandom.populate(); err != nil {
		return nil, err
	}
	if !isClient {
		c.cookie = make([]byte, cookieLength)
		if _, err = rand.Read(c.cookie); err != nil {
			return nil, err
		}
	}

	// Trigger outbound
	c.startHandshakeOutbound()

	// Handle inbound
	go c.inboundLoop()

	select {
	case <-c.handshakeDoneSignal.Done():
		err = c.handshakeErr.load()
	case <-ctx.Done():
		err = errConnectTimeout
		c.handshakeErr.store(err)
		c.handshakeDoneSignal.Close()
	}

	if err != nil {
		c.close() //nolint
	} else {
		c.setHandshakeCompletedSuccessfully()
	}

	c.log.Trace(fmt.Sprintf("Handshake Completed (Error: %v)", err))

	return c, err
}

// Dial connects to the given network address and establishes a DTLS connection on top.
// Connection handshake will timeout using ConnectContextMaker in the Config.
// If you want to specify the timeout duration, use DialWithContext() instead.
func Dial(network string, raddr *net.UDPAddr, config *Config) (*Conn, error) {
	ctx, cancel := config.connectContextMaker()
	defer cancel()

	return DialWithContext(ctx, network, raddr, config)
}

// Client establishes a DTLS connection over an existing connection.
// Connection handshake will timeout using ConnectContextMaker in the Config.
// If you want to specify the timeout duration, use ClientWithContext() instead.
func Client(conn net.Conn, config *Config) (*Conn, error) {
	ctx, cancel := config.connectContextMaker()
	defer cancel()

	return ClientWithContext(ctx, conn, config)
}

// Server listens for incoming DTLS connections.
// Connection handshake will timeout using ConnectContextMaker in the Config.
// If you want to specify the timeout duration, use ServerWithContext() instead.
func Server(conn net.Conn, config *Config) (*Conn, error) {
	ctx, cancel := config.connectContextMaker()
	defer cancel()

	return ServerWithContext(ctx, conn, config)
}

// DialWithContext connects to the given network address and establishes a DTLS connection on top.
func DialWithContext(ctx context.Context, network string, raddr *net.UDPAddr, config *Config) (*Conn, error) {
	pConn, err := net.DialUDP(network, nil, raddr)
	if err != nil {
		return nil, err
	}
	return ClientWithContext(ctx, pConn, config)
}

// ClientWithContext establishes a DTLS connection over an existing connection.
func ClientWithContext(ctx context.Context, conn net.Conn, config *Config) (*Conn, error) {
	switch {
	case config == nil:
		return nil, errNoConfigProvided
	case config.PSK != nil && config.PSKIdentityHint == nil:
		return nil, errPSKAndIdentityMustBeSetForClient
	}

	return createConn(ctx, conn, clientFlightHandler, clientHandshakeHandler, config, true)
}

// ServerWithContext listens for incoming DTLS connections.
func ServerWithContext(ctx context.Context, conn net.Conn, config *Config) (*Conn, error) {
	switch {
	case config == nil:
		return nil, errNoConfigProvided
	case config.PSK == nil && len(config.Certificates) == 0:
		return nil, errServerMustHaveCertificate
	}

	return createConn(ctx, conn, serverFlightHandler, serverHandshakeHandler, config, false)
}

// Read reads data from the connection.
func (c *Conn) Read(p []byte) (n int, err error) {
	var out []byte
	var ok bool
	select {
	case out, ok = <-c.decrypted:
		// inboundLoop has closed but error has not been set yet
		if !ok {
			if err := c.handshakeErr.load(); err != nil {
				return 0, err
			}
			if c.connectionClosed.Err() != nil {
				return 0, io.EOF
			}
			if err := c.readErr.load(); err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
	case <-c.readDeadline.Done():
		return 0, context.DeadlineExceeded
	}
	if len(p) < len(out) {
		return 0, errBufferTooSmall
	}
	copy(p, out)
	return len(out), nil
}

// Write writes len(p) bytes from p to the DTLS connection
func (c *Conn) Write(p []byte) (int, error) {
	select {
	case <-c.writeDeadline.Done():
		return 0, context.DeadlineExceeded
	default:
	}

	if err := c.handshakeErr.load(); err != nil {
		return 0, err
	}
	if c.connectionClosed.Err() != nil {
		return 0, ErrConnClosed
	}
	if !c.isHandshakeCompletedSuccessfully() {
		return 0, errHandshakeInProgress
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.bufferPacket(&packet{
		record: &recordLayer{
			recordLayerHeader: recordLayerHeader{
				epoch:           c.getLocalEpoch(),
				protocolVersion: protocolVersion1_2,
			},
			content: &applicationData{
				data: p,
			},
		},
		shouldEncrypt: true,
	}); err != nil {
		return 0, err
	}

	return len(p), c.flushPacketBuffer()
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.close()
}

// RemoteCertificate exposes the remote certificate
func (c *Conn) RemoteCertificate() [][]byte {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.state.remoteCertificate
}

// SelectedSRTPProtectionProfile returns the selected SRTPProtectionProfile
func (c *Conn) SelectedSRTPProtectionProfile() (SRTPProtectionProfile, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.state.srtpProtectionProfile == 0 {
		return 0, false
	}

	return c.state.srtpProtectionProfile, true
}

// ExportKeyingMaterial from https://tools.ietf.org/html/rfc5705
// This allows protocols to use DTLS for key establishment, but
// then use some of the keying material for their own purposes
func (c *Conn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.getLocalEpoch() == 0 {
		return nil, errHandshakeInProgress
	} else if len(context) != 0 {
		return nil, errContextUnsupported
	} else if _, ok := invalidKeyingLabels[label]; ok {
		return nil, errReservedExportKeyingMaterial
	}

	localRandom, err := c.state.localRandom.Marshal()
	if err != nil {
		return nil, err
	}
	remoteRandom, err := c.state.remoteRandom.Marshal()
	if err != nil {
		return nil, err
	}

	seed := []byte(label)
	if c.state.isClient {
		seed = append(append(seed, localRandom...), remoteRandom...)
	} else {
		seed = append(append(seed, remoteRandom...), localRandom...)
	}
	return prfPHash(c.state.masterSecret, seed, length, c.state.cipherSuite.hashFunc())
}

func (c *Conn) bufferPacket(p *packet) error {
	if h, ok := p.record.content.(*handshake); ok {
		handshakeRaw, err := p.record.Marshal()
		if err != nil {
			return err
		}

		c.log.Tracef("[handshake] -> %s", h.handshakeHeader.handshakeType.String())
		c.handshakeCache.push(handshakeRaw[recordLayerHeaderSize:], h.handshakeHeader.messageSequence, h.handshakeHeader.handshakeType, c.state.isClient)
	}

	c.bufferedPackets = append(c.bufferedPackets, p)

	return nil
}

func (c *Conn) flushPacketBuffer() error {
	var rawPackets [][]byte

	for _, p := range c.bufferedPackets {
		if p.resetLocalSequenceNumber {
			atomic.StoreUint64(&c.state.localSequenceNumber, 0)
		}

		if h, ok := p.record.content.(*handshake); ok {
			rawHandshakePackets, err := c.processHandshakePacket(p, h)
			if err != nil {
				return err
			}

			rawPackets = append(rawPackets, rawHandshakePackets...)
		} else {
			rawPacket, err := c.processPacket(p)
			if err != nil {
				return err
			}

			rawPackets = [][]byte{rawPacket}
		}
	}

	c.bufferedPackets = []*packet{}
	compactedRawPackets := c.compactRawPackets(rawPackets)

	for _, compactedRawPackets := range compactedRawPackets {
		if _, err := c.nextConn.Write(compactedRawPackets); err != nil {
			return err
		}
	}

	return nil
}

func (c *Conn) compactRawPackets(rawPackets [][]byte) [][]byte {
	combinedRawPackets := make([][]byte, 0)
	currentCombinedRawPacket := make([]byte, 0)

	for _, rawPacket := range rawPackets {
		if len(currentCombinedRawPacket) > 0 && len(currentCombinedRawPacket)+len(rawPacket) >= c.maximumTransmissionUnit {
			combinedRawPackets = append(combinedRawPackets, currentCombinedRawPacket)
			currentCombinedRawPacket = []byte{}
		}
		currentCombinedRawPacket = append(currentCombinedRawPacket, rawPacket...)
	}

	combinedRawPackets = append(combinedRawPackets, currentCombinedRawPacket)

	return combinedRawPackets
}

func (c *Conn) processPacket(p *packet) ([]byte, error) {
	p.record.recordLayerHeader.sequenceNumber = atomic.LoadUint64(&c.state.localSequenceNumber)
	atomic.AddUint64(&c.state.localSequenceNumber, 1)

	rawPacket, err := p.record.Marshal()
	if err != nil {
		return nil, err
	}

	if p.shouldEncrypt {
		var err error
		rawPacket, err = c.state.cipherSuite.encrypt(p.record, rawPacket)
		if err != nil {
			return nil, err
		}
	}

	return rawPacket, nil
}

func (c *Conn) processHandshakePacket(p *packet, h *handshake) ([][]byte, error) {
	rawPackets := make([][]byte, 0)

	handshakeFragments, err := c.fragmentHandshake(h)
	if err != nil {
		return nil, err
	}

	for _, handshakeFragment := range handshakeFragments {
		recordLayerHeader := &recordLayerHeader{
			contentType:     p.record.recordLayerHeader.contentType,
			contentLen:      uint16(len(handshakeFragment)),
			protocolVersion: p.record.recordLayerHeader.protocolVersion,
			epoch:           p.record.recordLayerHeader.epoch,
			sequenceNumber:  atomic.LoadUint64(&c.state.localSequenceNumber),
		}

		atomic.AddUint64(&c.state.localSequenceNumber, 1)

		recordLayerHeaderBytes, err := recordLayerHeader.Marshal()
		if err != nil {
			return nil, err
		}

		rawPacket := append(recordLayerHeaderBytes, handshakeFragment...)
		if p.shouldEncrypt {
			var err error
			rawPacket, err = c.state.cipherSuite.encrypt(p.record, rawPacket)
			if err != nil {
				return nil, err
			}
		}

		rawPackets = append(rawPackets, rawPacket)
	}

	return rawPackets, nil
}

func (c *Conn) fragmentHandshake(h *handshake) ([][]byte, error) {
	content, err := h.handshakeMessage.Marshal()
	if err != nil {
		return nil, err
	}

	fragmentedHandshakes := make([][]byte, 0)

	contentFragments := splitBytes(content, c.maximumTransmissionUnit)
	if len(contentFragments) == 0 {
		contentFragments = [][]byte{
			{},
		}
	}

	offset := 0
	for _, contentFragment := range contentFragments {
		contentFragmentLen := len(contentFragment)

		handshakeHeaderFragment := &handshakeHeader{
			handshakeType:   h.handshakeHeader.handshakeType,
			length:          h.handshakeHeader.length,
			messageSequence: h.handshakeHeader.messageSequence,
			fragmentOffset:  uint32(offset),
			fragmentLength:  uint32(contentFragmentLen),
		}

		offset += contentFragmentLen

		handshakeHeaderFragmentRaw, err := handshakeHeaderFragment.Marshal()
		if err != nil {
			return nil, err
		}

		fragmentedHandshake := append(handshakeHeaderFragmentRaw, contentFragment...)
		fragmentedHandshakes = append(fragmentedHandshakes, fragmentedHandshake)
	}

	return fragmentedHandshakes, nil
}

func (c *Conn) inboundLoop() {
	defer func() {
		close(c.decrypted)
	}()

	b := make([]byte, inboundBufferSize)
	for {
		i, err := c.nextConn.Read(b)
		if err != nil {
			c.readErr.store(err)
			return
		}

		pkts, err := unpackDatagram(b[:i])
		if err != nil {
			c.readErr.store(err)
			return
		}

		for _, p := range pkts {
			alert, err := c.handleIncomingPacket(p)
			if alert != nil {
				if alertErr := c.notify(alert.alertLevel, alert.alertDescription); alertErr != nil {
					err = fmt.Errorf("%v %v", err, alertErr)
				}
			}
			if err != nil {
				c.readErr.store(err)
				return
			}
		}
	}
}

func (c *Conn) handleIncomingPacket(buf []byte) (*alert, error) {
	// TODO: avoid separate unmarshal
	h := &recordLayerHeader{}
	if err := h.Unmarshal(buf); err != nil {
		return &alert{alertLevelFatal, alertDecodeError}, err
	}

	if h.epoch < c.getRemoteEpoch() {
		if _, alertPtr, err := c.flightHandler(c); err != nil {
			return alertPtr, err
		}
	}

	if h.epoch != 0 {
		if c.state.cipherSuite == nil || !c.state.cipherSuite.isInitialized() {
			c.log.Debug("handleIncoming: Handshake not finished, dropping packet")
			return nil, nil
		}

		var err error
		buf, err = c.state.cipherSuite.decrypt(buf)
		if err != nil {
			c.log.Debugf("decrypt failed: %s", err)
			return nil, nil
		}
	}

	isHandshake, err := c.fragmentBuffer.push(append([]byte{}, buf...))
	if err != nil {
		return &alert{alertLevelFatal, alertDecodeError}, err
	} else if isHandshake {
		newHandshakeMessage := false
		for out := c.fragmentBuffer.pop(); out != nil; out = c.fragmentBuffer.pop() {
			rawHandshake := &handshake{}
			if err := rawHandshake.Unmarshal(out); err != nil {
				return &alert{alertLevelFatal, alertDecodeError}, err
			}

			if c.handshakeCache.push(out, rawHandshake.handshakeHeader.messageSequence, rawHandshake.handshakeHeader.handshakeType, !c.state.isClient) {
				newHandshakeMessage = true
			}
		}
		if !newHandshakeMessage {
			return nil, nil
		}

		c.lock.Lock()
		defer c.lock.Unlock()
		return c.handshakeMessageHandler(c)
	}

	r := &recordLayer{}
	if err := r.Unmarshal(buf); err != nil {
		return &alert{alertLevelFatal, alertDecodeError}, err
	}

	switch content := r.content.(type) {
	case *alert:
		c.log.Tracef("<- %s", content.String())
		if content.alertDescription == alertCloseNotify {
			return nil, c.Close()
		}
		return nil, fmt.Errorf("alert: %v", content)
	case *changeCipherSpec:
		c.log.Trace("<- ChangeCipherSpec")

		newRemoteEpoch := h.epoch + 1
		if c.getRemoteEpoch() < newRemoteEpoch {
			c.setRemoteEpoch(newRemoteEpoch)
		}
	case *applicationData:
		if h.epoch == 0 {
			return &alert{alertLevelFatal, alertUnexpectedMessage}, fmt.Errorf("ApplicationData with epoch of 0")
		}

		if err := c.handshakeErr.load(); err != nil {
			return nil, err
		}
		if c.connectionClosed.Err() != nil {
			return nil, io.EOF
		}

		select {
		case c.decrypted <- content.data:
		case <-c.connectionClosed.Done():
		}
	default:
		return &alert{alertLevelFatal, alertUnexpectedMessage}, fmt.Errorf("unhandled contentType %d", content.contentType())
	}
	return nil, nil
}

func (c *Conn) notify(level alertLevel, desc alertDescription) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.bufferPacket(&packet{
		record: &recordLayer{
			recordLayerHeader: recordLayerHeader{
				epoch:           c.getLocalEpoch(),
				protocolVersion: protocolVersion1_2,
			},
			content: &alert{
				alertLevel:       level,
				alertDescription: desc,
			},
		},
		shouldEncrypt: c.isHandshakeCompletedSuccessfully(),
	}); err != nil {
		return err
	}

	return c.flushPacketBuffer()
}

func (c *Conn) setHandshakeCompletedSuccessfully() {
	c.handshakeCompletedSuccessfully.Store(struct{ bool }{true})
}

func (c *Conn) isHandshakeCompletedSuccessfully() bool {
	boolean, _ := c.handshakeCompletedSuccessfully.Load().(struct{ bool })
	return boolean.bool
}

func (c *Conn) startHandshakeOutbound() {
	go func() {
		defer func() {
			if c.handshakeErr.load() != nil {
				if err := c.close(); err != nil {
					c.log.Errorf(fmt.Sprintf("Failed to close (%v)", err))
				}
			}
		}()
		for {
			var (
				isFinished bool
				alertPtr   *alert
				err        error
			)
			select {
			case <-c.handshakeDoneSignal.Done():
				return
			case <-c.workerTicker.C:
				isFinished, alertPtr, err = c.flightHandler(c)
			case <-c.currFlight.workerTrigger:
				isFinished, alertPtr, err = c.flightHandler(c)
			}

			if alertPtr != nil {
				if alertErr := c.notify(alertPtr.alertLevel, alertPtr.alertDescription); alertErr != nil {
					err = fmt.Errorf("%v %v", err, alertErr)
				}
			}

			switch {
			case err != nil:
				c.handshakeErr.store(err)
				return
			case c.readErr.load() != nil:
				c.handshakeErr.store(c.readErr.load()) // Promote readErr to handshakeErr during handshake
				return
			case isFinished:
				return // Handshake is complete
			}
		}
	}()
	c.currFlight.workerTrigger <- struct{}{}
}

func (c *Conn) close() error {
	if c.connectionClosed.Err() == nil && c.handshakeErr.load() == nil {
		c.notify(alertLevelFatal, alertCloseNotify) //nolint
	}

	c.workerTicker.Stop()
	c.handshakeDoneSignal.Close()
	c.connectionClosed.Close()
	return c.nextConn.Close()
}

func (c *Conn) setLocalEpoch(epoch uint16) {
	c.state.localEpoch.Store(epoch)
}

func (c *Conn) getLocalEpoch() uint16 {
	return c.state.localEpoch.Load().(uint16)
}

func (c *Conn) setRemoteEpoch(epoch uint16) {
	c.state.remoteEpoch.Store(epoch)
}

func (c *Conn) getRemoteEpoch() uint16 {
	return c.state.remoteEpoch.Load().(uint16)
}

// LocalAddr implements net.Conn.LocalAddr
func (c *Conn) LocalAddr() net.Addr {
	return c.nextConn.LocalAddr()
}

// RemoteAddr implements net.Conn.RemoteAddr
func (c *Conn) RemoteAddr() net.Addr {
	return c.nextConn.RemoteAddr()
}

// SetDeadline implements net.Conn.SetDeadline
func (c *Conn) SetDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return c.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn.SetReadDeadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	// Read deadline is fully managed by this layer.
	// Don't set read deadline to underlying connection.
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Set(t)
	return c.nextConn.SetWriteDeadline(t)
}
