package dtls

import (
	"bytes"
	"fmt"
)

func serverHandshakeHandler(c *Conn) error {

	handleSingleHandshake := func(buf []byte) error {
		rawHandshake := &handshake{}
		if err := rawHandshake.Unmarshal(buf); err != nil {
			return err
		}

		switch h := rawHandshake.handshakeMessage.(type) {
		case *handshakeMessageClientHello:
			if c.currFlight.get() == flight2 {
				if !bytes.Equal(c.cookie, h.cookie) {
					return errCookieMismatch
				}
				c.localSequenceNumber = 1
				if err := c.currFlight.set(flight4); err != nil {
					return err
				}
				break
			}

			c.remoteRandom = h.random

			if len(h.cipherSuites) == 0 {
				return errCipherSuiteNoIntersection
			}
			c.cipherSuite = h.cipherSuites[0] // TODO assert we support (No RSA)

			for _, extension := range h.extensions {
				switch e := extension.(type) {
				case *extensionSupportedEllipticCurves:
					c.namedCurve = e.ellipticCurves[0]
				case *extensionUseSRTP:
					profile, ok := findMatchingSRTPProfile(e.protectionProfiles, c.localSRTPProtectionProfiles)
					if !ok {
						return fmt.Errorf("Client requested SRTP but we have no matching profiles")
					}
					c.srtpProtectionProfile = profile
				}
			}

			if c.localKeypair == nil {
				var err error
				c.localKeypair, err = generateKeypair(c.namedCurve)
				if err != nil {
					return err
				}
			}

			if err := c.currFlight.set(flight2); err != nil {
				return err
			}

		case *handshakeMessageCertificateVerify:
			if c.remoteCertificate == nil {
				return errCertificateVerifyNoCertificate
			}

			plainText := c.handshakeCache.pullAndMerge(
				handshakeCachePullRule{handshakeTypeClientHello, true},
				handshakeCachePullRule{handshakeTypeServerHello, false},
				handshakeCachePullRule{handshakeTypeCertificate, false},
				handshakeCachePullRule{handshakeTypeServerKeyExchange, false},
				handshakeCachePullRule{handshakeTypeCertificateRequest, false},
				handshakeCachePullRule{handshakeTypeServerHelloDone, false},
				handshakeCachePullRule{handshakeTypeCertificate, true},
				handshakeCachePullRule{handshakeTypeClientKeyExchange, true},
			)

			if err := verifyCertificateVerify(plainText, h.hashAlgorithm, h.signature, c.remoteCertificate); err != nil {
				return err
			}
			c.remoteCertificateVerified = true

		case *handshakeMessageCertificate:
			c.remoteCertificate = h.certificate

		case *handshakeMessageClientKeyExchange:
			c.remoteKeypair = &namedCurveKeypair{c.namedCurve, h.publicKey, nil}

			serverRandom, err := c.localRandom.Marshal()
			if err != nil {
				return err
			}
			clientRandom, err := c.remoteRandom.Marshal()
			if err != nil {
				return err
			}

			preMasterSecret, err := prfPreMasterSecret(c.remoteKeypair.publicKey, c.localKeypair.privateKey, c.localKeypair.curve)
			if err != nil {
				return err
			}

			c.masterSecret, err = prfMasterSecret(preMasterSecret, clientRandom, serverRandom, c.cipherSuite.hashFunc())
			if err != nil {
				return err
			}

			if err := c.cipherSuite.init(c.masterSecret, clientRandom, serverRandom /* isClient */, false); err != nil {
				return err
			}

		case *handshakeMessageFinished:
			plainText := c.handshakeCache.pullAndMerge(
				handshakeCachePullRule{handshakeTypeClientHello, true},
				handshakeCachePullRule{handshakeTypeServerHello, false},
				handshakeCachePullRule{handshakeTypeCertificate, false},
				handshakeCachePullRule{handshakeTypeServerKeyExchange, false},
				handshakeCachePullRule{handshakeTypeCertificateRequest, false},
				handshakeCachePullRule{handshakeTypeServerHelloDone, false},
				handshakeCachePullRule{handshakeTypeCertificate, true},
				handshakeCachePullRule{handshakeTypeClientKeyExchange, true},
				handshakeCachePullRule{handshakeTypeCertificateVerify, true},
			)
			expectedVerifyData, err := prfVerifyDataClient(c.masterSecret, plainText, c.cipherSuite.hashFunc())
			if err != nil {
				return err
			} else if !bytes.Equal(expectedVerifyData, h.verifyData) {
				return errVerifyDataMismatch
			}

		default:
			return fmt.Errorf("unhandled handshake %d", h.handshakeType())
		}

		return nil
	}

	switch c.currFlight.get() {
	case flight0:
		expectedMessages := c.handshakeCache.pull(
			handshakeCachePullRule{handshakeTypeClientHello, true},
		)
		if expectedMessages[0] != nil && expectedMessages[0].messageSequence == 0 {
			return handleSingleHandshake(expectedMessages[0].data)
		}
	case flight2:
		expectedMessages := c.handshakeCache.pull(
			handshakeCachePullRule{handshakeTypeClientHello, true},
		)
		if expectedMessages[0] != nil && expectedMessages[0].messageSequence == 1 {
			return handleSingleHandshake(expectedMessages[0].data)
		}
	case flight4:
		expectedMessages := c.handshakeCache.pull(
			handshakeCachePullRule{handshakeTypeCertificate, true},
			handshakeCachePullRule{handshakeTypeClientKeyExchange, true},
			handshakeCachePullRule{handshakeTypeCertificateVerify, true},
		)

		var expectedSeqnum uint16
		switch {
		case expectedMessages[0] != nil:
			expectedSeqnum = expectedMessages[0].messageSequence
		case expectedMessages[1] != nil:
			expectedSeqnum = expectedMessages[1].messageSequence
		default:
			return nil
		}

		for i, msg := range expectedMessages {
			// handshakeTypeCertificate and handshakeTypeCertificateVerify can be nil, just make sure we have no gaps
			switch {
			case (i == 0 || i == 2) && msg == nil:
				continue
			case msg == nil:
				return nil // We don't have all messages yet, try again later
			case msg.messageSequence != expectedSeqnum:
				return nil // We have a gap, still waiting on messages
			}
			expectedSeqnum++
		}

		for _, msg := range expectedMessages {
			if msg != nil {
				if err := handleSingleHandshake(msg.data); err != nil {
					return err
				}
			}
		}

		finishedMsg := c.handshakeCache.pull(handshakeCachePullRule{handshakeTypeFinished, true})
		if finishedMsg[0] == nil {
			return nil
		} else if err := handleSingleHandshake(finishedMsg[0].data); err != nil {
			return err
		}

		if c.clientAuth == RequireAnyClientCert && c.remoteCertificate == nil {
			return errClientCertificateRequired
		} else if c.remoteCertificate != nil && !c.remoteCertificateVerified {
			return errClientCertificateNotVerified
		}

		if c.clientAuth > NoClientCert {
			c.localSequenceNumber = 6
		} else {
			c.localSequenceNumber = 5
		}
		c.setLocalEpoch(1)

		if err := c.currFlight.set(flight6); err != nil {
			return err
		}
	}
	return nil
}

func serverFlightHandler(c *Conn) (bool, error) {
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

		extensions := []extension{
			&extensionSupportedEllipticCurves{
				ellipticCurves: []namedCurve{namedCurveX25519, namedCurveP256},
			},
			&extensionSupportedPointFormats{
				pointFormats: []ellipticCurvePointFormat{ellipticCurvePointFormatUncompressed},
			},
		}
		if c.srtpProtectionProfile != 0 {
			extensions = append(extensions, &extensionUseSRTP{
				protectionProfiles: []SRTPProtectionProfile{c.srtpProtectionProfile},
			})
		}

		sequenceNumber := c.localSequenceNumber
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
				handshakeMessage: &handshakeMessageServerHello{
					version:           protocolVersion1_2,
					random:            c.localRandom,
					cipherSuite:       c.cipherSuite,
					compressionMethod: defaultCompressionMethods[0],
					extensions:        extensions,
				}},
		}, false)
		sequenceNumber++

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
				handshakeMessage: &handshakeMessageCertificate{
					certificate: c.localCertificate,
				}},
		}, false)
		sequenceNumber++

		if len(c.localKeySignature) == 0 {
			serverRandom, err := c.localRandom.Marshal()
			if err != nil {
				return false, err
			}
			clientRandom, err := c.remoteRandom.Marshal()
			if err != nil {
				return false, err
			}

			signature, err := generateKeySignature(clientRandom, serverRandom, c.localKeypair.publicKey, c.namedCurve, c.localPrivateKey, HashAlgorithmSHA256)
			if err != nil {
				return false, err
			}
			c.localKeySignature = signature
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
				handshakeMessage: &handshakeMessageServerKeyExchange{
					ellipticCurveType:  ellipticCurveTypeNamedCurve,
					namedCurve:         c.namedCurve,
					publicKey:          c.localKeypair.publicKey,
					hashAlgorithm:      HashAlgorithmSHA256,
					signatureAlgorithm: signatureAlgorithmECDSA,
					signature:          c.localKeySignature,
				}},
		}, false)
		sequenceNumber++

		if c.clientAuth > NoClientCert {
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
					handshakeMessage: &handshakeMessageCertificateRequest{
						certificateTypes: []clientCertificateType{clientCertificateTypeRSASign, clientCertificateTypeECDSASign},
						signatureHashAlgorithms: []signatureHashAlgorithm{
							{HashAlgorithmSHA256, signatureAlgorithmRSA},
							{HashAlgorithmSHA384, signatureAlgorithmRSA},
							{HashAlgorithmSHA512, signatureAlgorithmRSA},
							{HashAlgorithmSHA256, signatureAlgorithmECDSA},
							{HashAlgorithmSHA384, signatureAlgorithmECDSA},
							{HashAlgorithmSHA512, signatureAlgorithmECDSA},
						},
					},
				},
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
			plainText := c.handshakeCache.pullAndMerge(
				handshakeCachePullRule{handshakeTypeClientHello, true},
				handshakeCachePullRule{handshakeTypeServerHello, false},
				handshakeCachePullRule{handshakeTypeCertificate, false},
				handshakeCachePullRule{handshakeTypeServerKeyExchange, false},
				handshakeCachePullRule{handshakeTypeCertificateRequest, false},
				handshakeCachePullRule{handshakeTypeServerHelloDone, false},
				handshakeCachePullRule{handshakeTypeCertificate, true},
				handshakeCachePullRule{handshakeTypeClientKeyExchange, true},
				handshakeCachePullRule{handshakeTypeCertificateVerify, true},
				handshakeCachePullRule{handshakeTypeFinished, true},
			)

			var err error
			c.localVerifyData, err = prfVerifyDataServer(c.masterSecret, plainText, c.cipherSuite.hashFunc())
			if err != nil {
				return false, err
			}
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

		// TODO: Better way to end handshake
		c.signalHandshakeComplete()
		return true, nil
	default:
		return false, fmt.Errorf("unhandled flight %s", c.currFlight.get())
	}
	return false, nil
}
