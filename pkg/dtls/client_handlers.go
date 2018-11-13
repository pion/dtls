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
		c.handshakeCache.push(out, fragEpoch, rawHandshake.handshakeHeader.messageSequence /* isLocal */, false)

		switch h := rawHandshake.handshakeMessage.(type) {
		case *handshakeMessageHelloVerifyRequest:
			c.cookie = append([]byte{}, h.cookie...)
			c.outboundSequenceNumber = 1
			c.currFlight.set(flight3)
		case *handshakeMessageServerHello:
			c.cipherSuite = h.cipherSuite
			c.remoteRandom = h.random
		case *handshakeMessageCertificate:
			c.remoteCertificate = h.certificate
		case *handshakeMessageServerKeyExchange:
			c.remoteKeypair = &namedCurveKeypair{h.namedCurve, h.publicKey, nil}
		case *handshakeMessageServerHelloDone:
			if c.remoteKeypair != nil && c.remoteCertificate != nil {
				preMasterSecret, err := prfPreMasterSecret(c.remoteKeypair.publicKey, c.localKeypair.privateKey, c.localKeypair.curve)
				if err != nil {
					return err
				}
				clientRandom, err := c.localRandom.marshal()
				if err != nil {
					return err
				}
				serverRandom, err := c.remoteRandom.marshal()
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

				c.outboundSequenceNumber = 2
				c.currFlight.set(flight5)
			}
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
					sequenceNumber:  c.outboundSequenceNumber,
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					// sequenceNumber and messageSequence line up, may need to be re-evaluated
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(c.outboundSequenceNumber),
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
			c.internalSend(&recordLayer{
				recordLayerHeader: recordLayerHeader{
					sequenceNumber:  c.outboundSequenceNumber,
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					// sequenceNumber and messageSequence line up, may need to be re-evaluated
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(c.outboundSequenceNumber),
					},
					handshakeMessage: &handshakeMessageClientKeyExchange{
						publicKey: c.localKeypair.publicKey,
					}},
			}, false)
			c.internalSend(&recordLayer{
				recordLayerHeader: recordLayerHeader{
					sequenceNumber:  c.outboundSequenceNumber + 1,
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
					sequenceNumber:  0,
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					// sequenceNumber and messageSequence line up, may need to be re-evaluated
					handshakeHeader: handshakeHeader{
						messageSequence: 3,
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
