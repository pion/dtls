package dtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const initialTickerInterval = time.Second
const cookieLength = 20
const defaultNamedCurve = namedCurveX25519

var invalidKeyingLabels = map[string]bool{
	"client finished": true,
	"server finished": true,
	"master secret":   true,
	"key expansion":   true,
}

type handshakeMessageHandler func(*Conn) error
type flightHandler func(*Conn) (bool, error)

// Conn represents a DTLS connection
type Conn struct {
	lock           sync.RWMutex    // Internal lock (must not be public)
	nextConn       net.Conn        // Embedded Conn, typically a udpconn we read/write from
	fragmentBuffer *fragmentBuffer // out-of-order and missing fragment handling
	handshakeCache *handshakeCache // caching of handshake messages for verifyData generation
	decrypted      chan []byte     // Decrypted Application Data, pull by calling `Read`
	workerTicker   *time.Ticker

	isClient                   bool
	remoteRequestedCertificate bool // Did we get a CertificateRequest
	localEpoch, remoteEpoch    atomic.Value
	localSequenceNumber        uint64 // uint48

	localSRTPProtectionProfiles []SRTPProtectionProfile // Available SRTPProtectionProfiles, if empty no SRTP support
	srtpProtectionProfile       SRTPProtectionProfile   // Negotiated SRTPProtectionProfile

	clientAuth ClientAuthType // If we are a client should we request a client certificate

	currFlight                          *flight
	cipherSuite                         cipherSuite // nil if a cipherSuite hasn't been chosen
	namedCurve                          namedCurve
	localRandom, remoteRandom           handshakeRandom
	localCertificate, remoteCertificate *x509.Certificate
	localPrivateKey                     crypto.PrivateKey
	localKeypair, remoteKeypair         *namedCurveKeypair
	cookie                              []byte

	localCertificateVerify    []byte // cache CertificateVerify
	localVerifyData           []byte // cached VerifyData
	remoteCertificateVerified bool

	masterSecret []byte

	handshakeMessageHandler handshakeMessageHandler
	flightHandler           flightHandler
	handshakeCompleted      chan bool

	connErr atomic.Value
}

func createConn(nextConn net.Conn, flightHandler flightHandler, handshakeMessageHandler handshakeMessageHandler, config *Config, isClient bool) (*Conn, error) {
	if config == nil {
		return nil, errors.New("no config provided")
	}

	if config.PrivateKey != nil {
		if _, ok := config.PrivateKey.(*ecdsa.PrivateKey); !ok {
			return nil, errInvalidPrivateKey
		}
	} else if nextConn == nil {
		return nil, errNilNextConn
	}

	c := &Conn{
		isClient:                    isClient,
		nextConn:                    nextConn,
		currFlight:                  newFlight(isClient),
		fragmentBuffer:              newFragmentBuffer(),
		handshakeCache:              newHandshakeCache(),
		handshakeMessageHandler:     handshakeMessageHandler,
		flightHandler:               flightHandler,
		localCertificate:            config.Certificate,
		localPrivateKey:             config.PrivateKey,
		clientAuth:                  config.ClientAuth,
		localSRTPProtectionProfiles: config.SRTPProtectionProfiles,
		namedCurve:                  defaultNamedCurve,

		decrypted:          make(chan []byte),
		workerTicker:       time.NewTicker(initialTickerInterval),
		handshakeCompleted: make(chan bool),
	}

	var zeroEpoch uint16
	c.localEpoch.Store(zeroEpoch)
	c.remoteEpoch.Store(zeroEpoch)

	err := c.localRandom.populate()
	if err != nil {
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
	go func() {
		defer func() {
			close(c.decrypted)
		}()

		b := make([]byte, 8192)
		for {
			i, err := c.nextConn.Read(b)
			if err != nil {
				c.stopWithError(err)
				return
			} else if c.getConnErr() != nil {
				return
			}

			if err := c.handleIncoming(b[:i]); err != nil {
				c.stopWithError(err)
				return
			}
		}
	}()

	<-c.handshakeCompleted
	return c, c.getConnErr()
}

// Dial connects to the given network address and establishes a DTLS connection on top
func Dial(network string, raddr *net.UDPAddr, config *Config) (*Conn, error) {
	pConn, err := net.DialUDP(network, nil, raddr)
	if err != nil {
		return nil, err
	}
	return Client(pConn, config)
}

// Client establishes a DTLS connection over an existing conn
func Client(conn net.Conn, config *Config) (*Conn, error) {
	return createConn(conn, clientFlightHandler, clientHandshakeHandler, config, true)
}

// Server listens for incoming DTLS connections
func Server(conn net.Conn, config *Config) (*Conn, error) {
	if config == nil || config.Certificate == nil {
		return nil, errServerMustHaveCertificate
	}
	return createConn(conn, serverFlightHandler, serverHandshakeHandler, config, false)
}

// Read reads data from the connection.
func (c *Conn) Read(p []byte) (n int, err error) {
	out, ok := <-c.decrypted
	if !ok {
		return 0, c.getConnErr()
	}
	if len(p) < len(out) {
		return 0, errBufferTooSmall
	}

	copy(p, out)
	return len(out), nil
}

// Write writes len(p) bytes from p to the DTLS connection
func (c *Conn) Write(p []byte) (int, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.getLocalEpoch() == 0 {
		return 0, errHandshakeInProgress
	} else if c.getConnErr() != nil {
		return 0, c.getConnErr()
	}

	c.internalSend(&recordLayer{
		recordLayerHeader: recordLayerHeader{
			epoch:           c.getLocalEpoch(),
			sequenceNumber:  c.localSequenceNumber,
			protocolVersion: protocolVersion1_2,
		},
		content: &applicationData{
			data: p,
		},
	}, true)
	c.localSequenceNumber++

	return len(p), nil
}

// Close closes the connection.
func (c *Conn) Close() error {
	c.notify(alertLevelFatal, alertCloseNotify)
	c.stopWithError(ErrConnClosed)
	if err := c.getConnErr(); err != ErrConnClosed {
		return err
	}
	return nil
}

// RemoteCertificate exposes the remote certificate
func (c *Conn) RemoteCertificate() *x509.Certificate {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.remoteCertificate
}

// SelectedSRTPProtectionProfile returns the selected SRTPProtectionProfile
func (c *Conn) SelectedSRTPProtectionProfile() (SRTPProtectionProfile, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.srtpProtectionProfile == 0 {
		return 0, false
	}

	return c.srtpProtectionProfile, true
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

	localRandom, err := c.localRandom.Marshal()
	if err != nil {
		return nil, err
	}
	remoteRandom, err := c.remoteRandom.Marshal()
	if err != nil {
		return nil, err
	}

	seed := []byte(label)
	if c.isClient {
		seed = append(append(seed, localRandom...), remoteRandom...)
	} else {
		seed = append(append(seed, remoteRandom...), localRandom...)
	}
	return prfPHash(c.masterSecret, seed, length, c.cipherSuite.hashFunc())
}

func (c *Conn) internalSend(pkt *recordLayer, shouldEncrypt bool) {
	raw, err := pkt.Marshal()
	if err != nil {
		c.stopWithError(err)
		return
	}

	if h, ok := pkt.content.(*handshake); ok {
		c.handshakeCache.push(raw[recordLayerHeaderSize:], pkt.recordLayerHeader.epoch,
			h.handshakeHeader.messageSequence /* isLocal */, true, c.currFlight.get())
	}

	if shouldEncrypt {
		raw, err = c.cipherSuite.encrypt(pkt, raw)
		if err != nil {
			c.stopWithError(err)
			return
		}
	}

	if _, err := c.nextConn.Write(raw); err != nil {
		c.stopWithError(err)
	}
}

func (c *Conn) handleIncoming(buf []byte) error {
	pkts, err := unpackDatagram(buf)
	if err != nil {
		return err
	}

	for _, p := range pkts {
		err := c.handleIncomingPacket(p)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) handleIncomingPacket(buf []byte) error {
	// TODO: avoid separate unmarshal
	h := &recordLayerHeader{}
	if err := h.Unmarshal(buf); err != nil {
		return err
	}
	if h.epoch < c.getRemoteEpoch() {
		fmt.Println("handleIncoming: old epoch, dropping packet")
		return nil
	}

	if c.getRemoteEpoch() != 0 {
		if c.cipherSuite == nil {
			fmt.Println("handleIncoming: Handshake not finished, dropping packet")
			return nil
		}

		var err error
		buf, err = c.cipherSuite.decrypt(buf)
		if err != nil {
			fmt.Println(err)
			return nil
		}
	}

	pushSuccess, err := c.fragmentBuffer.push(buf)
	if err != nil {
		return err
	} else if pushSuccess {
		// This was a fragmented buffer, therefore a handshake
		return c.handshakeMessageHandler(c)
	}

	r := &recordLayer{}
	if err := r.Unmarshal(buf); err != nil {
		return err
	}

	switch content := r.content.(type) {
	case *alert:
		if content.alertDescription == alertCloseNotify {
			return c.Close()
		}
		return fmt.Errorf("alert: %v", content)
	case *changeCipherSpec:
		c.setRemoteEpoch(c.getRemoteEpoch() + 1)
	case *applicationData:
		c.decrypted <- content.data
	default:
		return fmt.Errorf("unhandled contentType %d", content.contentType())
	}
	return nil
}

func (c *Conn) notify(level alertLevel, desc alertDescription) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.internalSend(&recordLayer{
		recordLayerHeader: recordLayerHeader{
			epoch:           c.getLocalEpoch(),
			sequenceNumber:  c.localSequenceNumber,
			protocolVersion: protocolVersion1_2,
		},
		content: &alert{
			alertLevel:       level,
			alertDescription: desc,
		},
	}, true)

	c.localSequenceNumber++
}

func (c *Conn) signalHandshakeComplete() {
	select {
	case <-c.handshakeCompleted:
	default:
		close(c.handshakeCompleted)
	}
}

func (c *Conn) startHandshakeOutbound() {
	go func() {
		for {
			var (
				isFinished bool
				err        error
			)
			select {
			case <-c.handshakeCompleted:
				return
			case <-c.workerTicker.C:
				isFinished, err = c.flightHandler(c)
			case <-c.currFlight.workerTrigger:
				isFinished, err = c.flightHandler(c)
			}

			switch {
			case err != nil:
				c.stopWithError(err)
				return
			case c.getConnErr() != nil:
				return
			case isFinished:
				return // Handshake is complete
			}
		}
	}()
}

func (c *Conn) stopWithError(err error) {
	if connErr := c.nextConn.Close(); connErr != nil {
		if err != ErrConnClosed {
			connErr = fmt.Errorf("%v\n%v", err, connErr)
		}
		err = connErr
	}

	c.connErr.Store(struct{ error }{err})

	c.workerTicker.Stop()

	c.signalHandshakeComplete()
}

func (c *Conn) getConnErr() error {
	err, _ := c.connErr.Load().(struct{ error })
	return err.error
}

func (c *Conn) setLocalEpoch(epoch uint16) {
	c.localEpoch.Store(epoch)
}

func (c *Conn) getLocalEpoch() uint16 {
	return c.localEpoch.Load().(uint16)
}

func (c *Conn) setRemoteEpoch(epoch uint16) {
	c.remoteEpoch.Store(epoch)
}

func (c *Conn) getRemoteEpoch() uint16 {
	return c.remoteEpoch.Load().(uint16)
}

// LocalAddr is a stub
func (c *Conn) LocalAddr() net.Addr {
	return c.nextConn.LocalAddr()
}

// RemoteAddr is a stub
func (c *Conn) RemoteAddr() net.Addr {
	return c.nextConn.RemoteAddr()
}

// SetDeadline is a stub
func (c *Conn) SetDeadline(t time.Time) error {
	return c.nextConn.SetDeadline(t)
}

// SetReadDeadline is a stub
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.nextConn.SetReadDeadline(t)
}

// SetWriteDeadline is a stub
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.nextConn.SetWriteDeadline(t)
}
