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
				c.localSequenceNumber++
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

				c.localKeypair, err = generateKeypair(h.namedCurve)
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
			c.remoteRequestedCertificate = true

		case *handshakeMessageServerHelloDone:
			if c.currFlight.get() == flight3 {
				c.localSequenceNumber++
				c.currFlight.set(flight5)
			}

		case *handshakeMessageFinished:
			if c.currFlight.get() == flight5 {
				c.localEpoch = 1
				c.localSequenceNumber = 1
				// TODO: verify

				// Signal handshake completed
				select {
				case <-c.handshakeCompleted:
				default:
					close(c.handshakeCompleted)
				}
			}

		default:
			return fmt.Errorf("Unhandled handshake %d", h.handshakeType())
		}
	}

	return nil
}

func clientTimerThread(c *Conn) {
	for {
		select {
		case <-c.workerTicker.C:
			clientFlightHandler(c)
		case <-c.currFlight.workerTrigger:
			clientFlightHandler(c)
		}
	}
}

func clientFlightHandler(c *Conn) {
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
						&extensionSupportedEllipticCurves{
							ellipticCurves: []namedCurve{namedCurveX25519, namedCurveP256},
						},
						&extensionUseSRTP{
							protectionProfiles: []srtpProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
						},
						&extensionSupportedPointFormats{
							pointFormats: []ellipticCurvePointFormat{ellipticCurvePointFormatUncompressed},
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

		// ClientHello and HelloVerifyRequest MUST NOT be included in the CertificateVerify
		excludeRules := map[flightVal]handshakeCacheExcludeRule{}
		if len(c.cookie) != 0 {
			excludeRules[flight0] = handshakeCacheExcludeRule{isLocal: true, isRemote: true}
			excludeRules[flight1] = handshakeCacheExcludeRule{isLocal: true, isRemote: true}
			excludeRules[flight2] = handshakeCacheExcludeRule{isLocal: true, isRemote: true}
		}

		sequenceNumber := c.localSequenceNumber

		if c.remoteRequestedCertificate {
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
			sequenceNumber++
		}

		c.internalSend(&recordLayer{
			recordLayerHeader: recordLayerHeader{
				sequenceNumber:  sequenceNumber,
				protocolVersion: protocolVersion1_2,
			},
			content: &handshake{
				// sequenceNumber and messageSequence line up, may need to be re-evaluated
				handshakeHeader: handshakeHeader{
					messageSequence: uint16(sequenceNumber),
				},
				handshakeMessage: &handshakeMessageClientKeyExchange{
					publicKey: c.localKeypair.publicKey,
				}},
		}, false)
		sequenceNumber++

		if c.remoteRequestedCertificate {
			if len(c.localCertificateVerify) == 0 {
				certVerify, err := generateCertificateVerify(c.handshakeCache.combinedHandshake(excludeRules), c.localPrivateKey)
				if err != nil {
					panic(err)
				}
				c.localCertificateVerify = certVerify
			}

			c.internalSend(&recordLayer{
				recordLayerHeader: recordLayerHeader{
					sequenceNumber:  sequenceNumber,
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					// sequenceNumber and messageSequence line up, may need to be re-evaluated
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(sequenceNumber),
					},
					handshakeMessage: &handshakeMessageCertificateVerify{
						hashAlgorithm:      HashAlgorithmSHA256,
						signatureAlgorithm: signatureAlgorithmECDSA,
						signature:          c.localCertificateVerify,
					}},
			}, false)
			sequenceNumber++
		}

		c.internalSend(&recordLayer{
			recordLayerHeader: recordLayerHeader{
				sequenceNumber:  sequenceNumber,
				protocolVersion: protocolVersion1_2,
			},
			content: &changeCipherSpec{},
		}, false)

		if len(c.localVerifyData) == 0 {
			c.localVerifyData = prfVerifyDataClient(c.keys.masterSecret, c.handshakeCache.combinedHandshake(excludeRules))
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
					messageSequence: uint16(sequenceNumber), // KeyExchange + 1
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
