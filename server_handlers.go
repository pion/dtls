package dtls

import (
	"bytes"
	"crypto/x509"
	"fmt"
)

func serverHandshakeHandler(c *Conn) (*alert, error) {
	handleSingleHandshake := func(buf []byte) (*alert, error) {
		rawHandshake := &handshake{}
		if err := rawHandshake.Unmarshal(buf); err != nil {
			return &alert{alertLevelFatal, alertDecodeError}, err
		}

		switch h := rawHandshake.handshakeMessage.(type) {
		case *handshakeMessageClientHello:
			if c.currFlight.get() == flight2 {
				if !bytes.Equal(c.cookie, h.cookie) {
					return &alert{alertLevelFatal, alertAccessDenied}, errCookieMismatch
				}
				c.handshakeMessageSequence = 1
				c.currFlight.set(flight4)
				break
			}

			c.state.remoteRandom = h.random

			if _, ok := findMatchingCipherSuite(h.cipherSuites, c.localCipherSuites); !ok {
				return &alert{alertLevelFatal, alertInsufficientSecurity}, errCipherSuiteNoIntersection
			}
			c.state.cipherSuite = h.cipherSuites[0]

			for _, extension := range h.extensions {
				switch e := extension.(type) {
				case *extensionSupportedEllipticCurves:
					if len(e.ellipticCurves) == 0 {
						return &alert{alertLevelFatal, alertInsufficientSecurity}, errNoSupportedEllipticCurves
					}
					c.namedCurve = e.ellipticCurves[0]
				case *extensionUseSRTP:
					profile, ok := findMatchingSRTPProfile(e.protectionProfiles, c.localSRTPProtectionProfiles)
					if !ok {
						return &alert{alertLevelFatal, alertInsufficientSecurity}, errServerNoMatchingSRTPProfile
					}
					c.state.srtpProtectionProfile = profile
				case *extensionUseExtendedMasterSecret:
					if c.extendedMasterSecret != DisableExtendedMasterSecret {
						c.state.extendedMasterSecret = true
					}
				}
			}

			if c.extendedMasterSecret == RequireExtendedMasterSecret && !c.state.extendedMasterSecret {
				return &alert{alertLevelFatal, alertInsufficientSecurity}, errServerRequiredButNoClientEMS
			}

			if c.localKeypair == nil {
				var err error
				c.localKeypair, err = generateKeypair(c.namedCurve)
				if err != nil {
					return &alert{alertLevelFatal, alertIllegalParameter}, err
				}
			}

			c.currFlight.set(flight2)

		case *handshakeMessageCertificateVerify:
			if c.state.remoteCertificate == nil {
				return &alert{alertLevelFatal, alertNoCertificate}, errCertificateVerifyNoCertificate
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

			if err := verifyCertificateVerify(plainText, h.hashAlgorithm, h.signature, c.state.remoteCertificate); err != nil {
				return &alert{alertLevelFatal, alertBadCertificate}, err
			}
			var chains [][]*x509.Certificate
			var err error
			var verified bool
			if c.clientAuth >= VerifyClientCertIfGiven {
				if chains, err = verifyClientCert(c.state.remoteCertificate, c.clientCAs); err != nil {
					return &alert{alertLevelFatal, alertBadCertificate}, err
				}
				verified = true
			}
			if c.verifyPeerCertificate != nil {
				if err := c.verifyPeerCertificate(c.state.remoteCertificate, chains); err != nil {
					return &alert{alertLevelFatal, alertBadCertificate}, err
				}
			}
			c.remoteCertificateVerified = verified

		case *handshakeMessageCertificate:
			c.state.remoteCertificate = h.certificate

		case *handshakeMessageClientKeyExchange:
			serverRandom, err := c.state.localRandom.Marshal()
			if err != nil {
				return &alert{alertLevelFatal, alertInternalError}, err
			}
			clientRandom, err := c.state.remoteRandom.Marshal()
			if err != nil {
				return &alert{alertLevelFatal, alertInternalError}, err
			}

			var preMasterSecret []byte
			if c.localPSKCallback != nil {
				var psk []byte
				if psk, err = c.localPSKCallback(h.identityHint); err != nil {
					return &alert{alertLevelFatal, alertInternalError}, err
				}

				preMasterSecret = prfPSKPreMasterSecret(psk)
			} else {
				preMasterSecret, err = prfPreMasterSecret(h.publicKey, c.localKeypair.privateKey, c.localKeypair.curve)
				if err != nil {
					return &alert{alertLevelFatal, alertIllegalParameter}, err
				}
			}

			if c.state.extendedMasterSecret {
				var sessionHash []byte
				sessionHash, err = c.handshakeCache.sessionHash(c.state.cipherSuite.hashFunc())
				if err != nil {
					return &alert{alertLevelFatal, alertInternalError}, err
				}

				c.state.masterSecret, err = prfExtendedMasterSecret(preMasterSecret, sessionHash, c.state.cipherSuite.hashFunc())
				if err != nil {
					return &alert{alertLevelFatal, alertInternalError}, err
				}
			} else {
				c.state.masterSecret, err = prfMasterSecret(preMasterSecret, clientRandom, serverRandom, c.state.cipherSuite.hashFunc())
				if err != nil {
					return &alert{alertLevelFatal, alertInternalError}, err
				}
			}

			if err := c.state.cipherSuite.init(c.state.masterSecret, clientRandom, serverRandom /* isClient */, false); err != nil {
				return &alert{alertLevelFatal, alertInternalError}, err
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
			expectedVerifyData, err := prfVerifyDataClient(c.state.masterSecret, plainText, c.state.cipherSuite.hashFunc())
			if err != nil {
				return &alert{alertLevelFatal, alertInternalError}, err
			} else if !bytes.Equal(expectedVerifyData, h.verifyData) {
				return &alert{alertLevelFatal, alertHandshakeFailure}, errVerifyDataMismatch
			}

		default:
			return &alert{alertLevelFatal, alertUnexpectedMessage}, fmt.Errorf("unhandled handshake %d", h.handshakeType())
		}

		return nil, nil
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
			return nil, nil
		}

		for i, msg := range expectedMessages {
			// handshakeTypeCertificate and handshakeTypeCertificateVerify can be nil, just make sure we have no gaps
			switch {
			case (i == 0 || i == 2) && msg == nil:
				continue
			case msg == nil:
				return nil, nil // We don't have all messages yet, try again later
			case msg.messageSequence != expectedSeqnum:
				return nil, nil // We have a gap, still waiting on messages
			}
			expectedSeqnum++
		}

		for _, msg := range expectedMessages {
			if msg != nil {
				if alertPtr, err := handleSingleHandshake(msg.data); err != nil {
					return alertPtr, err
				}
			}
		}

		finishedMsg := c.handshakeCache.pull(handshakeCachePullRule{handshakeTypeFinished, true})
		if finishedMsg[0] == nil {
			return nil, nil
		} else if alertPtr, err := handleSingleHandshake(finishedMsg[0].data); err != nil {
			return alertPtr, err
		}

		switch c.clientAuth {
		case RequireAnyClientCert:
			if c.state.remoteCertificate == nil {
				return &alert{alertLevelFatal, alertNoCertificate}, errClientCertificateRequired
			}
		case VerifyClientCertIfGiven:
			if c.state.remoteCertificate != nil && !c.remoteCertificateVerified {
				return &alert{alertLevelFatal, alertBadCertificate}, errClientCertificateNotVerified
			}
		case RequireAndVerifyClientCert:
			if c.state.remoteCertificate == nil {
				return &alert{alertLevelFatal, alertNoCertificate}, errClientCertificateRequired
			}
			if !c.remoteCertificateVerified {
				return &alert{alertLevelFatal, alertBadCertificate}, errClientCertificateNotVerified
			}
		}

		switch {
		case c.localPSKIdentityHint != nil:
			c.handshakeMessageSequence = 4
		case c.localPSKCallback != nil:
			c.handshakeMessageSequence = 3
		case c.clientAuth > NoClientCert:
			c.handshakeMessageSequence = 6
		default:
			c.handshakeMessageSequence = 5
		}

		c.setLocalEpoch(1)
		c.currFlight.set(flight6)
	}
	return nil, nil
}

func serverFlightHandler(c *Conn) (bool, *alert, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	switch c.currFlight.get() {
	case flight0:
		// Waiting for ClientHello
	case flight2:
		if err := c.bufferPacket(&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(c.handshakeMessageSequence),
					},
					handshakeMessage: &handshakeMessageHelloVerifyRequest{
						version: protocolVersion1_2,
						cookie:  c.cookie,
					},
				},
			},
		}); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}
		if err := c.flushPacketBuffer(); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}

	case flight4:
		extensions := []extension{}
		if (c.extendedMasterSecret == RequestExtendedMasterSecret ||
			c.extendedMasterSecret == RequireExtendedMasterSecret) && c.state.extendedMasterSecret {
			extensions = append(extensions, &extensionUseExtendedMasterSecret{
				supported: true,
			})
		}
		if c.state.srtpProtectionProfile != 0 {
			extensions = append(extensions, &extensionUseSRTP{
				protectionProfiles: []SRTPProtectionProfile{c.state.srtpProtectionProfile},
			})
		}
		if c.localPSKCallback == nil {
			extensions = append(extensions, []extension{
				&extensionSupportedEllipticCurves{
					ellipticCurves: []namedCurve{namedCurveX25519, namedCurveP256, namedCurveP384},
				},
				&extensionSupportedPointFormats{
					pointFormats: []ellipticCurvePointFormat{ellipticCurvePointFormatUncompressed},
				},
			}...)
		}

		messageSequence := c.handshakeMessageSequence
		if err := c.bufferPacket(&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(messageSequence),
					},
					handshakeMessage: &handshakeMessageServerHello{
						version:           protocolVersion1_2,
						random:            c.state.localRandom,
						cipherSuite:       c.state.cipherSuite,
						compressionMethod: defaultCompressionMethods[0],
						extensions:        extensions,
					}},
			},
		}); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}
		messageSequence++

		if c.localPSKCallback == nil {
			var certificate [][]byte
			if len(c.localCertificates) > 0 {
				certificate = c.localCertificates[0].Certificate
			}
			if err := c.bufferPacket(&packet{
				record: &recordLayer{
					recordLayerHeader: recordLayerHeader{
						protocolVersion: protocolVersion1_2,
					},
					content: &handshake{
						handshakeHeader: handshakeHeader{
							messageSequence: uint16(messageSequence),
						},
						handshakeMessage: &handshakeMessageCertificate{
							certificate: certificate,
						}},
				},
			}); err != nil {
				return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
			}
			messageSequence++

			if len(c.localKeySignature) == 0 {
				serverRandom, err := c.state.localRandom.Marshal()
				if err != nil {
					return false, &alert{alertLevelFatal, alertInternalError}, err
				}
				clientRandom, err := c.state.remoteRandom.Marshal()
				if err != nil {
					return false, &alert{alertLevelFatal, alertInternalError}, err
				}

				signature, err := generateKeySignature(clientRandom, serverRandom, c.localKeypair.publicKey, c.namedCurve, c.localCertificates[0].PrivateKey, hashAlgorithmSHA256)
				if err != nil {
					return false, &alert{alertLevelFatal, alertInternalError}, err
				}
				c.localKeySignature = signature
			}

			if err := c.bufferPacket(&packet{
				record: &recordLayer{
					recordLayerHeader: recordLayerHeader{
						protocolVersion: protocolVersion1_2,
					},
					content: &handshake{
						handshakeHeader: handshakeHeader{
							messageSequence: uint16(messageSequence),
						},
						handshakeMessage: &handshakeMessageServerKeyExchange{
							ellipticCurveType:  ellipticCurveTypeNamedCurve,
							namedCurve:         c.namedCurve,
							publicKey:          c.localKeypair.publicKey,
							hashAlgorithm:      hashAlgorithmSHA256,
							signatureAlgorithm: signatureAlgorithmECDSA,
							signature:          c.localKeySignature,
						}},
				},
			}); err != nil {
				return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
			}
			messageSequence++

			if c.clientAuth > NoClientCert {
				if err := c.bufferPacket(&packet{
					record: &recordLayer{
						recordLayerHeader: recordLayerHeader{
							protocolVersion: protocolVersion1_2,
						},
						content: &handshake{
							handshakeHeader: handshakeHeader{
								messageSequence: uint16(messageSequence),
							},
							handshakeMessage: &handshakeMessageCertificateRequest{
								certificateTypes: []clientCertificateType{clientCertificateTypeRSASign, clientCertificateTypeECDSASign},
								signatureHashAlgorithms: []signatureHashAlgorithm{
									{hashAlgorithmSHA256, signatureAlgorithmRSA},
									{hashAlgorithmSHA384, signatureAlgorithmRSA},
									{hashAlgorithmSHA512, signatureAlgorithmRSA},
									{hashAlgorithmSHA256, signatureAlgorithmECDSA},
									{hashAlgorithmSHA384, signatureAlgorithmECDSA},
									{hashAlgorithmSHA512, signatureAlgorithmECDSA},
								},
							},
						},
					},
				}); err != nil {
					return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
				}
				messageSequence++
			}
		} else if c.localPSKIdentityHint != nil {
			/* To help the client in selecting which identity to use, the server
			*  can provide a "PSK identity hint" in the ServerKeyExchange message.
			*  If no hint is provided, the ServerKeyExchange message is omitted.
			*
			*  https://tools.ietf.org/html/rfc4279#section-2
			 */
			if err := c.bufferPacket(&packet{
				record: &recordLayer{
					recordLayerHeader: recordLayerHeader{
						protocolVersion: protocolVersion1_2,
					},
					content: &handshake{
						handshakeHeader: handshakeHeader{
							messageSequence: uint16(messageSequence),
						},
						handshakeMessage: &handshakeMessageServerKeyExchange{
							identityHint: c.localPSKIdentityHint,
						}},
				},
			}); err != nil {
				return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
			}
			messageSequence++
		}

		if err := c.bufferPacket(&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(messageSequence),
					},
					handshakeMessage: &handshakeMessageServerHelloDone{},
				},
			},
		}); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}

		if err := c.flushPacketBuffer(); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}
	case flight6:
		if err := c.bufferPacket(&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &changeCipherSpec{},
			},
		}); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}

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
			c.localVerifyData, err = prfVerifyDataServer(c.state.masterSecret, plainText, c.state.cipherSuite.hashFunc())
			if err != nil {
				return false, &alert{alertLevelFatal, alertInternalError}, err
			}
		}

		if err := c.bufferPacket(&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					epoch:           1,
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(c.handshakeMessageSequence),
					},

					handshakeMessage: &handshakeMessageFinished{
						verifyData: c.localVerifyData,
					}},
			},
			shouldEncrypt:            true,
			resetLocalSequenceNumber: true,
		}); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}

		if err := c.flushPacketBuffer(); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}

		c.handshakeDoneSignal.Close()
		return true, nil, nil
	default:
		return false, &alert{alertLevelFatal, alertUnexpectedMessage}, fmt.Errorf("unhandled flight %s", c.currFlight.get())
	}
	return false, nil, nil
}
