package dtls

import (
	"bytes"
	"fmt"
)

func serverHandshakeHandler(c *Conn) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	for out, fragEpoch := c.fragmentBuffer.pop(); out != nil; out, fragEpoch = c.fragmentBuffer.pop() {
		rawHandshake := &handshake{}
		if err := rawHandshake.unmarshal(out); err != nil {
			return err
		}
		c.handshakeCache.push(out, fragEpoch, rawHandshake.handshakeHeader.messageSequence /* isLocal */, false, c.currFlight.get())

		switch h := rawHandshake.handshakeMessage.(type) {
		case *handshakeMessageClientHello:
			if c.currFlight.get() == flight2 {
				if !bytes.Equal(c.cookie, h.cookie) {
					return errCookieMismatch
				}
				c.localSequenceNumber = 1
				c.currFlight.set(flight4)
				break
			}

			c.remoteRandom = h.random
			if len(h.cipherSuites) == 0 {
				return errCipherSuiteNoIntersection
			}
			c.cipherSuite = h.cipherSuites[0]
			c.currFlight.set(flight2)
		default:
			return fmt.Errorf("Unhandled handshake %d", h.handshakeType())
		}
	}

	return nil
}

func serverTimerThread(c *Conn) {
	for range c.workerTicker.C {
		switch c.currFlight.get() {
		case flight0:
			// Waiting for ClientHello
		case flight2:
			c.lock.RLock()
			c.internalSend(&recordLayer{
				recordLayerHeader: recordLayerHeader{
					sequenceNumber:  c.localSequenceNumber,
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					// sequenceNumber and messageSequence line up, may need to be re-evaluated
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(c.localSequenceNumber),
					},
					handshakeMessage: &handshakeMessageHelloVerifyRequest{
						version: protocolVersion1_2,
						cookie:  c.cookie,
					},
				},
			}, false)
			c.lock.RUnlock()
		default:
			panic(fmt.Errorf("Unhandled flight %s", c.currFlight.get()))
		}
	}
}
