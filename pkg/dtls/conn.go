package dtls

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const initialTickerInterval = time.Second
const cookieLength = 20

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
	localEpoch, remoteEpoch    uint16
	localSequenceNumber        uint64 // uint48

	currFlight                          *flight
	cipherSuite                         *cipherSuite // nil if a cipherSuite hasn't been chosen
	localRandom, remoteRandom           handshakeRandom
	localCertificate, remoteCertificate *x509.Certificate
	localPrivateKey                     *ecdsa.PrivateKey
	localKeypair, remoteKeypair         *namedCurveKeypair
	cookie                              []byte

	localCertificateVerify []byte // cache CertificateVerify
	localVerifyData        []byte // cached VerifyData

	keys                *encryptionKeys
	localGCM, remoteGCM cipher.AEAD

	handshakeMessageHandler handshakeMessageHandler
	flightHandler           flightHandler
	handshakeCompleted      chan struct{}

	connErr error
}

func createConn(nextConn net.Conn, flightHandler flightHandler, handshakeMessageHandler handshakeMessageHandler, config *Config, isClient bool) (*Conn, error) {
	if config == nil {
		return nil, errors.New("No config provided")
	}

	var localPrivateKey *ecdsa.PrivateKey

	if config.PrivateKey != nil {
		switch k := config.PrivateKey.(type) {
		case *ecdsa.PrivateKey:
			localPrivateKey = k
		default:
			return nil, errInvalidPrivateKey
		}
	} else if nextConn == nil {
		return nil, errNilNextConn
	}

	c := &Conn{
		isClient:                isClient,
		nextConn:                nextConn,
		currFlight:              newFlight(isClient),
		fragmentBuffer:          newFragmentBuffer(),
		handshakeCache:          newHandshakeCache(),
		handshakeMessageHandler: handshakeMessageHandler,
		flightHandler:           flightHandler,
		localCertificate:        config.Certificate,
		localPrivateKey:         localPrivateKey,

		decrypted:          make(chan []byte),
		workerTicker:       time.NewTicker(initialTickerInterval),
		handshakeCompleted: make(chan struct{}),
	}
	c.localRandom.populate()
	if !isClient {
		c.cookie = make([]byte, cookieLength)
		if _, err := rand.Read(c.cookie); err != nil {
			return nil, err
		}

		// TODO keypair generation should account for supported remote curves
		c.localKeypair, _ = generateKeypair(namedCurveX25519)
	}

	// Trigger outbound
	c.startHandshakeOutbound()

	// Handle inbound
	go func() {
		b := make([]byte, 8192)
		for {
			i, err := c.nextConn.Read(b)
			if err != nil {
				c.stopWithError(err)
				return
			} else if c.connErr != nil {
				return
			}

			if err := c.handleIncoming(b[:i]); err != nil {
				c.stopWithError(err)
				return
			}
		}
	}()

	<-c.handshakeCompleted
	return c, c.connErr
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
		return 0, c.connErr
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
	if c.localEpoch == 0 {
		return 0, errHandshakeInProgress
	} else if c.connErr != nil {
		return 0, c.connErr
	}

	c.internalSend(&recordLayer{
		recordLayerHeader: recordLayerHeader{
			epoch:           c.localEpoch,
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
	return c.nextConn.Close()
}

// RemoteCertificate exposes the remote certificate
func (c *Conn) RemoteCertificate() *x509.Certificate {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.remoteCertificate
}

// ExportKeyingMaterial from https://tools.ietf.org/html/rfc5705
// This allows protocols to use DTLS for key establishment, but
// then use some of the keying material for their own purposes
func (c *Conn) ExportKeyingMaterial(label []byte, context []byte, length int) ([]byte, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.localEpoch == 0 {
		return nil, errHandshakeInProgress
	} else if len(context) != 0 {
		return nil, errContextUnsupported
	}
	switch string(label) {
	case "client finished", "server finished", "master secret", "key expansion":
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

	seed := append([]byte{}, label...)
	if c.isClient {
		seed = append(append(seed, localRandom...), remoteRandom...)
	} else {
		seed = append(append(seed, remoteRandom...), localRandom...)
	}
	return prfPHash(c.keys.masterSecret, seed, length), nil
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
		raw, err = encryptPacket(pkt, raw, c.getLocalWriteIV(), c.localGCM)
		if err != nil {
			c.stopWithError(err)
			return
		}
	}

	c.nextConn.Write(raw)
}

func (c *Conn) getLocalWriteIV() []byte {
	if c.isClient {
		return c.keys.clientWriteIV
	}
	return c.keys.serverWriteIV
}

func (c *Conn) getRemoteWriteIV() []byte {
	if c.isClient {
		return c.keys.serverWriteIV
	}
	return c.keys.clientWriteIV
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
	if h.epoch < c.remoteEpoch {
		fmt.Println("handleIncoming: old epoch, dropping packet")
		return nil
	}

	if c.remoteEpoch != 0 {
		if c.remoteGCM == nil {
			fmt.Println("handleIncoming: Handshake not finished, dropping packet")
			return nil
		}

		var err error
		buf, err = decryptPacket(buf, c.getRemoteWriteIV(), c.remoteGCM)
		if err != nil {
			return err
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
		c.remoteEpoch++
	case *applicationData:
		c.decrypted <- content.data
	default:
		return fmt.Errorf("Unhandled contentType %d", content.contentType())
	}
	return nil
}

func (c *Conn) notify(level alertLevel, desc alertDescription) {
	c.internalSend(&recordLayer{
		recordLayerHeader: recordLayerHeader{
			epoch:           c.localEpoch,
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
			case <-c.workerTicker.C:
				isFinished, err = c.flightHandler(c)
			case <-c.currFlight.workerTrigger:
				isFinished, err = c.flightHandler(c)
			}

			if err != nil {
				c.stopWithError(err)
				return
			} else if c.connErr != nil {
				return
			} else if isFinished {
				return // Handshake is complete
			}
		}
	}()
}

func (c *Conn) stopWithError(err error) {
	c.connErr = err

	close(c.decrypted)
	c.workerTicker.Stop()

	c.signalHandshakeComplete()
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
