package dtls

import "fmt"

func clientHandshakeHandler(c *Conn) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	for out, fragEpoch := c.fragmentBuffer.pop(); out != nil; out, fragEpoch = c.fragmentBuffer.pop() {
		rawHandshake := &handshake{}
		if err := rawHandshake.unmarshal(out); err != nil {
			return err
		}
		c.handshakeCache.push(out, fragEpoch, rawHandshake.handshakeHeader.messageSequence /* isLocal */, false, c.currFlight.get())

		switch h := rawHandshake.handshakeMessage.(type) {
		case *handshakeMessageHelloVerifyRequest:
			if c.currFlight.get() == flight1 {
				c.cookie = append([]byte{}, h.cookie...)
				c.localSequenceNumber = 1
				c.currFlight.set(flight3)
			}

		case *handshakeMessageServerHello:
			switch c.currFlight.get() {
			case flight1:
				// HelloVerifyRequest can be skipped by the server
				c.currFlight.set(flight3)
				fallthrough
			case flight3:
				c.cipherSuite = h.cipherSuite
				c.remoteRandom = h.random
			}

		case *handshakeMessageCertificate:
			if c.currFlight.get() == flight3 {
				c.remoteCertificate = h.certificate
			}

		case *handshakeMessageServerKeyExchange:
			if c.currFlight.get() == flight3 {
				c.remoteKeypair = &namedCurveKeypair{h.namedCurve, h.publicKey, nil}

				clientRandom, err := c.localRandom.marshal()
				if err != nil {
					return err
				}
				serverRandom, err := c.remoteRandom.marshal()
				if err != nil {
					return err
				}
				preMasterSecret, err := prfPreMasterSecret(c.remoteKeypair.publicKey, c.localKeypair.privateKey, c.localKeypair.curve)
				if err != nil {
					return err
				}

				c.keys = prfEncryptionKeys(prfMasterSecret(preMasterSecret, clientRandom, serverRandom), clientRandom, serverRandom)
				c.localGCM, err = newAESGCM(c.keys.clientWriteKey)
				if err != nil {
					return err
				}

				c.remoteGCM, err = newAESGCM(c.keys.serverWriteKey)
				if err != nil {
					return err
				}
			}

		case *handshakeMessageCertificateRequest:
			// TODO

		case *handshakeMessageServerHelloDone:
			if c.currFlight.get() == flight3 {
				c.localSequenceNumber = 2
				c.currFlight.set(flight5)
			}

		case *handshakeMessageFinished:
			c.localEpoch = 1
			c.localSequenceNumber = 1
			fmt.Println("Handshake finished")
			// TODO: verify

		default:
			return fmt.Errorf("Unhandled handshake %d", h.handshakeType())
		}
	}

	return nil
}

func clientTimerThread(c *Conn) {
	for range c.workerTicker.C {
		switch c.currFlight.get() {
		case flight1:
			fallthrough
		case flight3:
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
					handshakeMessage: &handshakeMessageClientHello{
						version:            protocolVersion1_2,
						cookie:             c.cookie,
						random:             c.localRandom,
						cipherSuites:       defaultCipherSuites,
						compressionMethods: defaultCompressionMethods,
						extensions: []extension{
							&extensionSupportedGroups{
								supportedGroups: []namedCurve{namedCurveX25519, namedCurveP256},
							},
						},
					}},
			}, false)
			c.lock.RUnlock()
		case flight5:
			c.lock.RLock()
			// TODO: Better way to end handshake
			if c.remoteEpoch != 0 {
				// Handshake is done
				c.lock.RUnlock()
				return
			}

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
					handshakeMessage: &handshakeMessageCertificate{
						certificate: c.localCertificate,
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
					handshakeMessage: &handshakeMessageClientKeyExchange{
						publicKey: c.localKeypair.publicKey,
					}},
			}, false)

			c.internalSend(&recordLayer{
				recordLayerHeader: recordLayerHeader{
					sequenceNumber:  c.localSequenceNumber + 2,
					protocolVersion: protocolVersion1_2,
				},
				content: &changeCipherSpec{},
			}, false)

			if len(c.localVerifyData) == 0 {
				c.localVerifyData = prfVerifyDataClient(c.keys.masterSecret, c.handshakeCache.combinedHandshake())
			}

			// TODO: Fix hard-coded epoch & sequenceNumber, taking retransmitting into account.
			c.internalSend(&recordLayer{
				recordLayerHeader: recordLayerHeader{
					epoch:           1,
					sequenceNumber:  0, // sequenceNumber restarts per epoch
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					// sequenceNumber and messageSequence line up, may need to be re-evaluated
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(c.localSequenceNumber + 2), // KeyExchange + 1
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
