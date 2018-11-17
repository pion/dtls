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

		fmt.Printf("serverHandshakeHandler %T\n", rawHandshake.handshakeMessage)
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

		case *handshakeMessageClientKeyExchange:
			if c.currFlight.get() == flight4 {
				c.remoteKeypair = &namedCurveKeypair{namedCurveX25519, h.publicKey, nil}

				serverRandom, err := c.localRandom.marshal()
				if err != nil {
					return err
				}
				clientRandom, err := c.remoteRandom.marshal()
				if err != nil {
					return err
				}
				preMasterSecret, err := prfPreMasterSecret(c.remoteKeypair.publicKey, c.localKeypair.privateKey, c.localKeypair.curve)
				if err != nil {
					return err
				}

				c.keys = prfEncryptionKeys(prfMasterSecret(preMasterSecret, clientRandom, serverRandom), clientRandom, serverRandom)
				c.remoteGCM, err = newAESGCM(c.keys.clientWriteKey)
				if err != nil {
					return err
				}

				c.localGCM, err = newAESGCM(c.keys.serverWriteKey)
				if err != nil {
					return err
				}
			}

		case *handshakeMessageFinished:
			if c.currFlight.get() == flight4 {
				fmt.Println("Handshake finished")
				// TODO: verify
				c.localSequenceNumber = 6
				c.currFlight.set(flight6)
			}

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

		case flight4:
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
					handshakeMessage: &handshakeMessageServerHello{
						version:           protocolVersion1_2,
						random:            c.localRandom,
						cipherSuite:       defaultCipherSuites[0],       // TODO: Pick correct cipher suite
						compressionMethod: defaultCompressionMethods[0], // TODO: Pick correct cipher suite
						extensions: []extension{
							&extensionSupportedGroups{
								supportedGroups: []namedCurve{namedCurveX25519, namedCurveP256},
							},
						},
					}},
			}, false)

			c.internalSend(&recordLayer{
				recordLayerHeader: recordLayerHeader{
					sequenceNumber:  c.localSequenceNumber + 1,
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					// sequenceNumber and messageSequence line up, may need to be re-evaluated
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(c.localSequenceNumber + 1),
					},
					handshakeMessage: &handshakeMessageCertificate{
						certificate: c.localCertificate,
					}},
			}, false)

			c.internalSend(&recordLayer{
				recordLayerHeader: recordLayerHeader{
					sequenceNumber:  c.localSequenceNumber + 2,
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					// sequenceNumber and messageSequence line up, may need to be re-evaluated
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(c.localSequenceNumber + 2),
					},
					handshakeMessage: &handshakeMessageServerKeyExchange{
						ellipticCurveType:  ellipticCurveTypeNamedCurve,
						namedCurve:         c.localKeypair.curve,
						publicKey:          c.localKeypair.publicKey,
						hashAlgorithm:      hashAlgorithmSHA1,
						signatureAlgorithm: signatureAlgorithmECDSA,
						clientRandom:       &c.remoteRandom,
						serverRandom:       &c.localRandom,
					}},
			}, false)

			// TODO: CertificateRequest

			c.internalSend(&recordLayer{
				recordLayerHeader: recordLayerHeader{
					sequenceNumber:  c.localSequenceNumber + 3,
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					// sequenceNumber and messageSequence line up, may need to be re-evaluated
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(c.localSequenceNumber + 3),
					},
					handshakeMessage: &handshakeMessageServerHelloDone{},
				},
			}, false)
			c.lock.RUnlock()

		case flight6:
			c.lock.RLock()
			c.internalSend(&recordLayer{
				recordLayerHeader: recordLayerHeader{
					sequenceNumber:  c.localSequenceNumber,
					protocolVersion: protocolVersion1_2,
				},
				content: &changeCipherSpec{},
			}, false)

			if len(c.localVerifyData) == 0 {
				c.localVerifyData = prfVerifyDataClient(c.keys.masterSecret, c.handshakeCache.combinedHandshake())
			}

			c.internalSend(&recordLayer{
				recordLayerHeader: recordLayerHeader{
					epoch:           1,
					sequenceNumber:  0, // sequenceNumber restarts per epoch
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					// sequenceNumber and messageSequence line up, may need to be re-evaluated
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(c.localSequenceNumber), // KeyExchange + 1
					},

					handshakeMessage: &handshakeMessageFinished{
						verifyData: c.localVerifyData,
					}},
			}, true)
			c.lock.RUnlock()

		default:
			panic(fmt.Errorf("Unhandled flight %s", c.currFlight.get()))
		}
	}
}
