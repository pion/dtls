package dtls

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
)

const initialTickerInterval = time.Second
const finalTickerInternal = 90 * time.Second
const cookieLength = 20

type handshakeMessageHandler func(*Conn) error
type timerThread func(*Conn)

// Conn represents a DTLS connection
type Conn struct {
	lock           sync.RWMutex    // Internal lock (must not be public)
	nextConn       net.Conn        // Embedded Conn, typically a udpconn we read/write from
	fragmentBuffer *fragmentBuffer // out-of-order and missing fragment handling
	handshakeCache *handshakeCache // caching of handshake messages for verifyData generation
	decrypted      chan []byte     // Decrypted Application Data, pull by calling `Read`
	workerTicker   *time.Ticker

	remoteHasVerified       bool // Have we seen a handshake finished with a valid hash
	localEpoch, remoteEpoch uint16
	localSequenceNumber     uint64 // uint48

	currFlight                          *flight
	cipherSuite                         *cipherSuite // nil if a cipherSuite hasn't been chosen
	localRandom, remoteRandom           handshakeRandom
	localCertificate, remoteCertificate *x509.Certificate
	localKeypair, remoteKeypair         *namedCurveKeypair
	cookie                              []byte
	localVerifyData                     []byte // cached VerifyData

	keys                *encryptionKeys
	localGCM, remoteGCM cipher.AEAD

	handshakeMessageHandler handshakeMessageHandler
	timerThread             timerThread
}

func createConn(nextConn net.Conn, timerThread timerThread, handshakeMessageHandler handshakeMessageHandler, localCertificate *x509.Certificate, isClient bool) (*Conn, error) {
	c := &Conn{
		nextConn:                nextConn,
		currFlight:              newFlight(isClient),
		fragmentBuffer:          newFragmentBuffer(),
		handshakeCache:          newHandshakeCache(),
		handshakeMessageHandler: handshakeMessageHandler,
		timerThread:             timerThread,
		localCertificate:        localCertificate,

		decrypted:    make(chan []byte),
		workerTicker: time.NewTicker(initialTickerInterval),
	}
	c.localRandom.populate()
	c.localKeypair, _ = generateKeypair(namedCurveX25519)

	if !isClient {
		c.cookie = make([]byte, cookieLength)
		if _, err := rand.Read(c.cookie); err != nil {
			return nil, err
		}
	}

	go c.readThread()
	go c.timerThread(c)
	return c, nil
}

// Dial establishes a DTLS connection over an existing conn
func Dial(conn net.Conn, localCertificate *x509.Certificate) (*Conn, error) {
	return createConn(conn, clientTimerThread, clientHandshakeHandler, localCertificate /*isClient*/, true)
}

// Server listens for incoming DTLS connections
func Server(conn net.Conn, localCertificate *x509.Certificate) (*Conn, error) {
	if localCertificate == nil {
		return nil, errServerMustHaveCertificate
	}
	return createConn(conn, serverTimerThread, serverHandshakeHandler, localCertificate /*isClient*/, false)
}

// Read reads data from the connection.
func (c *Conn) Read(p []byte) (n int, err error) {
	out := <-c.decrypted
	if len(p) < len(out) {
		return 0, errBufferTooSmall
	}

	copy(p, out)
	return len(p), nil
}

// Write writes len(p) bytes from p to the DTLS connection
func (c *Conn) Write(p []byte) (n int, err error) {
	return // TODO encrypt + send ApplicationData
}

// Close closes the connection.
func (c *Conn) Close() error {
	c.nextConn.Close() // TODO Is there a better way to stop read in readThread?
	return nil
}

// Pulls from nextConn
func (c *Conn) readThread() {
	b := make([]byte, 8192)
	for {
		i, err := c.nextConn.Read(b)
		if err != nil {
			panic(err)
		}
		if err := c.handleIncoming(b[:i]); err != nil {
			panic(err)
		}
	}
}

func (c *Conn) encryptPacket(pkt *recordLayer, raw []byte) []byte {
	payload := raw[recordLayerHeaderSize:]
	raw = raw[:recordLayerHeaderSize]

	nonce := append(append([]byte{}, c.keys.clientWriteIV[:4]...), make([]byte, 8)...)
	if _, err := rand.Read(nonce[4:]); err != nil {
		panic(err)
	}

	var additionalData [13]byte
	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(additionalData[:], pkt.recordLayerHeader.sequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], pkt.recordLayerHeader.epoch)
	additionalData[8] = byte(pkt.content.contentType())
	additionalData[9] = pkt.recordLayerHeader.protocolVersion.major
	additionalData[10] = pkt.recordLayerHeader.protocolVersion.minor
	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(len(payload)))
	encryptedPayload := c.localGCM.Seal(nil, nonce, payload, additionalData[:])

	encryptedPayload = append(nonce[4:], encryptedPayload...)
	raw = append(raw, encryptedPayload...)

	// Update recordLayer size to include explicit nonce
	binary.BigEndian.PutUint16(raw[recordLayerHeaderSize-2:], uint16(len(raw)-recordLayerHeaderSize))
	return raw
}

func (c *Conn) decryptPacket(pkt *recordLayer, a *applicationData) ([]byte, error) {
	if len(a.data) <= 8 {
		return nil, errNotEnoughRoomForNonce
	}

	nonce := append(c.keys.serverWriteIV[:4], a.data[0:8]...)
	out := a.data[8:]

	var additionalData [13]byte
	// SequenceNumber MUST be set first
	// we only want uint48, clobbering an extra 2 (using uint64, Golang doesn't have uint48)
	binary.BigEndian.PutUint64(additionalData[:], pkt.recordLayerHeader.sequenceNumber)
	binary.BigEndian.PutUint16(additionalData[:], pkt.recordLayerHeader.epoch)
	additionalData[8] = byte(pkt.content.contentType())
	additionalData[9] = pkt.recordLayerHeader.protocolVersion.major
	additionalData[10] = pkt.recordLayerHeader.protocolVersion.minor
	binary.BigEndian.PutUint16(additionalData[len(additionalData)-2:], uint16(len(out)-aesGCMTagLength))
	return c.remoteGCM.Open(out[:0], nonce, out, additionalData[:])
}

func (c *Conn) internalSend(pkt *recordLayer, shouldEncrypt bool) {
	raw, err := pkt.marshal()
	if err != nil {
		panic(err)
	}

	if h, ok := pkt.content.(*handshake); ok {
		c.handshakeCache.push(raw[recordLayerHeaderSize:], pkt.recordLayerHeader.epoch,
			h.handshakeHeader.messageSequence /* isLocal */, true, c.currFlight.get())
	}

	if shouldEncrypt {
		raw = c.encryptPacket(pkt, raw)
	}

	c.nextConn.Write(raw)
}

func (c *Conn) handleIncoming(buf []byte) error {
	pkts, err := unpackDatagram(buf)
	if err != nil {
		return err
	}

	for _, p := range pkts {
		pushSuccess, err := c.fragmentBuffer.push(p)
		if err != nil {
			return err
		} else if pushSuccess {
			// This was a fragmented buffer, therefore a handshake
			return c.handshakeMessageHandler(c)
		}

		r := &recordLayer{}
		if err := r.unmarshal(p); err != nil {
			return err
		}

		switch content := r.content.(type) {
		case *alert:
			return fmt.Errorf(spew.Sdump(content))
		case *changeCipherSpec:
			c.remoteEpoch++
		case *applicationData:
			decrypted, err := c.decryptPacket(r, content)
			if err != nil {
				panic(err)
			}
			select {
			case c.decrypted <- decrypted:
			default:
			}
		default:
			return fmt.Errorf("Unhandled contentType %d", content.contentType())
		}
	}
	return nil
}
