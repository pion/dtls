package dtls

import (
	"bytes"
	"fmt"
)

func clientExcludeRules(c *Conn) map[flightVal]handshakeCacheExcludeRule {
	excludeRules := map[flightVal]handshakeCacheExcludeRule{}
	if len(c.cookie) != 0 {
		excludeRules[flight0] = handshakeCacheExcludeRule{isLocal: true, isRemote: true}
		excludeRules[flight1] = handshakeCacheExcludeRule{isLocal: true, isRemote: true}
		excludeRules[flight2] = handshakeCacheExcludeRule{isLocal: true, isRemote: true}
	}
	return excludeRules
}

func clientHandshakeHandler(c *Conn) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	for out, fragEpoch := c.fragmentBuffer.pop(); out != nil; out, fragEpoch = c.fragmentBuffer.pop() {
		rawHandshake := &handshake{}
		if err := rawHandshake.Unmarshal(out); err != nil {
			return err
		}
		c.handshakeCache.push(out, fragEpoch, rawHandshake.handshakeHeader.messageSequence /* isLocal */, false, c.currFlight.get())

		switch h := rawHandshake.handshakeMessage.(type) {
		case *handshakeMessageHelloVerifyRequest:
			if c.currFlight.get() == flight1 {
				c.cookie = append([]byte{}, h.cookie...)
				c.localSequenceNumber++
				if err := c.currFlight.set(flight3); err != nil {
					return err
				}
			}

		case *handshakeMessageServerHello:
			switch c.currFlight.get() {
			case flight1:
				// HelloVerifyRequest can be skipped by the server
				if err := c.currFlight.set(flight3); err != nil {
					return err
				}
				fallthrough
			case flight3:
				for _, extension := range h.extensions {
					if e, ok := extension.(*extensionUseSRTP); ok {
						profile, ok := findMatchingSRTPProfile(e.protectionProfiles, c.localSRTPProtectionProfiles)
						if !ok {
							return fmt.Errorf("Server responded with SRTP Profile we do not support")
						}
						c.srtpProtectionProfile = profile
					}
				}
				if len(c.localSRTPProtectionProfiles) > 0 && c.srtpProtectionProfile == 0 {
					return fmt.Errorf("SRTP support was requested but server did not respond with use_srtp extension")
				}

				c.cipherSuite = h.cipherSuite
				c.remoteRandom = h.random
			}

		case *handshakeMessageCertificate:
			if c.currFlight.get() == flight3 {
				c.remoteCertificate = h.certificate
			}

		case *handshakeMessageServerKeyExchange:
			if c.currFlight.get() == flight3 && c.cipherSuite != nil {
				c.remoteKeypair = &namedCurveKeypair{h.namedCurve, h.publicKey, nil}

				clientRandom, err := c.localRandom.Marshal()
				if err != nil {
					return err
				}
				serverRandom, err := c.remoteRandom.Marshal()
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

				c.masterSecret, err = prfMasterSecret(preMasterSecret, clientRandom, serverRandom, c.cipherSuite.hashFunc())
				if err != nil {
					return err
				}

				if err := c.cipherSuite.init(c.masterSecret, clientRandom, serverRandom /* isClient */, true); err != nil {
					return err
				}

				expectedHash := valueKeySignature(clientRandom, serverRandom, h.publicKey, h.namedCurve, h.hashAlgorithm)
				if err := verifyKeySignature(expectedHash, h.signature, h.hashAlgorithm, c.remoteCertificate); err != nil {
					return err
				}
			}

		case *handshakeMessageCertificateRequest:
			c.remoteRequestedCertificate = true

		case *handshakeMessageServerHelloDone:
			if c.currFlight.get() == flight3 {
				c.localSequenceNumber++
				if err := c.currFlight.set(flight5); err != nil {
					return err
				}
			}

		case *handshakeMessageFinished:
			if c.currFlight.get() == flight5 {
				c.setLocalEpoch(1)
				c.localSequenceNumber = 1

				expectedVerifyData, err := prfVerifyDataServer(c.masterSecret, c.handshakeCache.combinedHandshake(clientExcludeRules(c), true), c.cipherSuite.hashFunc())
				if err != nil {
					return err
				}
				if !bytes.Equal(expectedVerifyData, h.verifyData) {
					return errVerifyDataMismatch
				}
				c.signalHandshakeComplete()
			}

		default:
			return fmt.Errorf("unhandled handshake %d", h.handshakeType())
		}
	}

	return nil
}

func clientFlightHandler(c *Conn) (bool, error) {
	switch c.currFlight.get() {
	case flight1:
		fallthrough
	case flight3:
		c.lock.RLock()

		extensions := []extension{
			&extensionSupportedEllipticCurves{
				ellipticCurves: []namedCurve{namedCurveX25519, namedCurveP256},
			},
			&extensionSupportedPointFormats{
				pointFormats: []ellipticCurvePointFormat{ellipticCurvePointFormatUncompressed},
			},
			&extensionSupportedSignatureAlgorithms{
				signatureHashAlgorithms: []signatureHashAlgorithm{
					{HashAlgorithmSHA256, signatureAlgorithmECDSA},
					{HashAlgorithmSHA384, signatureAlgorithmECDSA},
					{HashAlgorithmSHA512, signatureAlgorithmECDSA},
					{HashAlgorithmSHA256, signatureAlgorithmRSA},
					{HashAlgorithmSHA384, signatureAlgorithmRSA},
					{HashAlgorithmSHA512, signatureAlgorithmRSA},
				},
			},
		}
		if len(c.localSRTPProtectionProfiles) > 0 {
			extensions = append(extensions, &extensionUseSRTP{
				protectionProfiles: c.localSRTPProtectionProfiles,
			})
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
				handshakeMessage: &handshakeMessageClientHello{
					version:            protocolVersion1_2,
					cookie:             c.cookie,
					random:             c.localRandom,
					cipherSuites:       clientCipherSuites(),
					compressionMethods: defaultCompressionMethods,
					extensions:         extensions,
				}},
		}, false)
		c.lock.RUnlock()
	case flight5:
		// TODO: Better way to end handshake
		if c.getRemoteEpoch() != 0 {
			// Handshake is done
			return true, nil
		}

		c.lock.RLock()
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
				certVerify, err := generateCertificateVerify(c.handshakeCache.combinedHandshake(clientExcludeRules(c), false), c.localPrivateKey)
				if err != nil {
					return false, err
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
			var err error
			c.localVerifyData, err = prfVerifyDataClient(c.masterSecret, c.handshakeCache.combinedHandshake(clientExcludeRules(c), false), c.cipherSuite.hashFunc())
			if err != nil {
				return false, err
			}
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
		return false, fmt.Errorf("unhandled flight %s", c.currFlight.get())
	}
	return false, nil
}
