package dtls

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"sync/atomic"
)

func initalizeCipherSuite(c *Conn, h *handshakeMessageServerKeyExchange) (*alert, error) {
	clientRandom, err := c.state.localRandom.Marshal()
	if err != nil {
		return &alert{alertLevelFatal, alertInternalError}, err
	}
	serverRandom, err := c.state.remoteRandom.Marshal()
	if err != nil {
		return &alert{alertLevelFatal, alertInternalError}, err
	}

	if c.state.extendedMasterSecret {
		var sessionHash []byte
		sessionHash, err = c.handshakeCache.sessionHash(c.state.cipherSuite.hashFunc())
		if err != nil {
			return &alert{alertLevelFatal, alertInternalError}, err
		}

		c.state.masterSecret, err = prfExtendedMasterSecret(c.state.preMasterSecret, sessionHash, c.state.cipherSuite.hashFunc())
		if err != nil {
			return &alert{alertLevelFatal, alertIllegalParameter}, err
		}
	} else {
		c.state.masterSecret, err = prfMasterSecret(c.state.preMasterSecret, clientRandom, serverRandom, c.state.cipherSuite.hashFunc())
		if err != nil {
			return &alert{alertLevelFatal, alertInternalError}, err
		}
	}

	if c.localPSKCallback == nil {
		expectedHash := valueKeySignature(clientRandom, serverRandom, h.publicKey, h.namedCurve, h.hashAlgorithm)
		if err = verifyKeySignature(expectedHash, h.signature, h.hashAlgorithm, c.state.remoteCertificate); err != nil {
			return &alert{alertLevelFatal, alertBadCertificate}, err
		}
		var chains [][]*x509.Certificate
		if !c.insecureSkipVerify {
			if chains, err = verifyServerCert(c.state.remoteCertificate, c.rootCAs, c.serverName); err != nil {
				return &alert{alertLevelFatal, alertBadCertificate}, err
			}
		}
		if c.verifyPeerCertificate != nil {
			if err = c.verifyPeerCertificate(c.state.remoteCertificate, chains); err != nil {
				return &alert{alertLevelFatal, alertBadCertificate}, err
			}
		}
	}

	if err = c.state.cipherSuite.init(c.state.masterSecret, clientRandom, serverRandom /* isClient */, true); err != nil {
		return &alert{alertLevelFatal, alertInternalError}, err
	}
	return nil, nil
}

func handleServerKeyExchange(c *Conn, h *handshakeMessageServerKeyExchange) (*alert, error) {
	var err error
	if c.localPSKCallback != nil {
		var psk []byte
		if psk, err = c.localPSKCallback(h.identityHint); err != nil {
			return &alert{alertLevelFatal, alertInternalError}, err
		}

		c.state.preMasterSecret = prfPSKPreMasterSecret(psk)
	} else {
		if c.localKeypair, err = generateKeypair(h.namedCurve); err != nil {
			return &alert{alertLevelFatal, alertInternalError}, err
		}

		if c.state.preMasterSecret, err = prfPreMasterSecret(h.publicKey, c.localKeypair.privateKey, c.localKeypair.curve); err != nil {
			return &alert{alertLevelFatal, alertInternalError}, err
		}
	}

	return nil, nil
}

func clientHandshakeHandler(c *Conn) (*alert, error) {
	handleSingleHandshake := func(buf []byte) (*alert, error) {
		rawHandshake := &handshake{}
		if err := rawHandshake.Unmarshal(buf); err != nil {
			return &alert{alertLevelFatal, alertDecodeError}, err
		}

		c.log.Tracef("[handshake] <- %s", rawHandshake.handshakeMessage.handshakeType().String())
		switch h := rawHandshake.handshakeMessage.(type) {
		case *handshakeMessageHelloVerifyRequest:
			c.cookie = append([]byte{}, h.cookie...)

		case *handshakeMessageServerHello:
			for _, extension := range h.extensions {
				switch e := extension.(type) {
				case *extensionUseSRTP:
					profile, ok := findMatchingSRTPProfile(e.protectionProfiles, c.localSRTPProtectionProfiles)
					if !ok {
						return &alert{alertLevelFatal, alertIllegalParameter}, errClientNoMatchingSRTPProfile
					}
					c.state.srtpProtectionProfile = profile
				case *extensionUseExtendedMasterSecret:
					if c.extendedMasterSecret != DisableExtendedMasterSecret {
						c.state.extendedMasterSecret = true
					}
				}
			}
			if c.extendedMasterSecret == RequireExtendedMasterSecret && !c.state.extendedMasterSecret {
				return &alert{alertLevelFatal, alertInsufficientSecurity}, errClientRequiredButNoServerEMS
			}
			if len(c.localSRTPProtectionProfiles) > 0 && c.state.srtpProtectionProfile == 0 {
				return &alert{alertLevelFatal, alertInsufficientSecurity}, errRequestedButNoSRTPExtension
			}
			if _, ok := findMatchingCipherSuite([]cipherSuite{h.cipherSuite}, c.localCipherSuites); !ok {
				return &alert{alertLevelFatal, alertInsufficientSecurity}, errCipherSuiteNoIntersection
			}

			c.state.cipherSuite = h.cipherSuite
			c.state.remoteRandom = h.random
			c.log.Tracef("[handshake] use cipher suite: %s", h.cipherSuite.String())

		case *handshakeMessageCertificate:
			c.state.remoteCertificate = h.certificate

		case *handshakeMessageServerKeyExchange:
			alertPtr, err := handleServerKeyExchange(c, h)
			if err != nil {
				return alertPtr, err
			}
		case *handshakeMessageCertificateRequest:
			c.remoteRequestedCertificate = true
		case *handshakeMessageServerHelloDone:
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
				handshakeCachePullRule{handshakeTypeFinished, true},
			)

			expectedVerifyData, err := prfVerifyDataServer(c.state.masterSecret, plainText, c.state.cipherSuite.hashFunc())
			if err != nil {
				return &alert{alertLevelFatal, alertInternalError}, err
			}
			if !bytes.Equal(expectedVerifyData, h.verifyData) {
				return &alert{alertLevelFatal, alertHandshakeFailure}, errVerifyDataMismatch
			}
		default:
			return &alert{alertLevelFatal, alertUnexpectedMessage}, fmt.Errorf("unhandled handshake %d", h.handshakeType())
		}

		return nil, nil
	}

	switch c.currFlight.get() {
	case flight1:
		// HelloVerifyRequest can be skipped by the server, so allow ServerHello during flight1 also
		expectedMessages := c.handshakeCache.pull(
			handshakeCachePullRule{handshakeTypeHelloVerifyRequest, false},
			handshakeCachePullRule{handshakeTypeServerHello, false},
		)

		switch {
		case expectedMessages[0] != nil:
			if alertPtr, err := handleSingleHandshake(expectedMessages[0].data); err != nil {
				return alertPtr, err
			}
			c.handshakeMessageSequence++
		case expectedMessages[1] != nil:
			if alertPtr, err := handleSingleHandshake(expectedMessages[1].data); err != nil {
				return alertPtr, err
			}
		default:
			return nil, nil // We have no messages we can handle yet
		}

		c.currFlight.set(flight3)
	case flight3:
		expectedMessages := c.handshakeCache.pull(
			handshakeCachePullRule{handshakeTypeServerHello, false},
			handshakeCachePullRule{handshakeTypeCertificate, false},
			handshakeCachePullRule{handshakeTypeServerKeyExchange, false},
			handshakeCachePullRule{handshakeTypeCertificateRequest, false},
			handshakeCachePullRule{handshakeTypeServerHelloDone, false},
		)
		// We don't have enough data to even assert validity
		if expectedMessages[0] == nil {
			return &alert{alertLevelFatal, alertHandshakeFailure}, nil
		}

		expectedSeqnum := expectedMessages[0].messageSequence
		for i, msg := range expectedMessages {
			switch {
			// handshakeTypeCertificate and handshakeTypeServerKeyExchange can be nil
			// when doing PSK
			case c.localPSKCallback != nil && (i == 1 || i == 2) && msg == nil:
				continue
			// handshakeMessageCertificateRequest can be nil
			case i == 3 && msg == nil:
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

		c.handshakeMessageSequence++
		c.currFlight.set(flight5)
	case flight5:
		expectedMessages := c.handshakeCache.pull(
			handshakeCachePullRule{handshakeTypeFinished, false},
		)

		if expectedMessages[0] == nil {
			return nil, nil
		} else if alertPtr, err := handleSingleHandshake(expectedMessages[0].data); err != nil {
			return alertPtr, err
		}

		c.setLocalEpoch(1)
		c.handshakeMessageSequence = 1
		atomic.StoreUint64(&c.state.localSequenceNumber, 1)
		c.handshakeDoneSignal.Close()
	default:
		return &alert{alertLevelFatal, alertUnexpectedMessage}, fmt.Errorf("client asked to handle unknown flight (%d)", c.currFlight.get())
	}

	return nil, nil
}

func clientFlightHandler(c *Conn) (bool, *alert, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	switch c.currFlight.get() {
	case flight1:
		fallthrough
	case flight3:
		extensions := []extension{
			&extensionSupportedSignatureAlgorithms{
				signatureHashAlgorithms: []signatureHashAlgorithm{
					{hashAlgorithmSHA256, signatureAlgorithmECDSA},
					{hashAlgorithmSHA384, signatureAlgorithmECDSA},
					{hashAlgorithmSHA512, signatureAlgorithmECDSA},
					{hashAlgorithmSHA256, signatureAlgorithmRSA},
					{hashAlgorithmSHA384, signatureAlgorithmRSA},
					{hashAlgorithmSHA512, signatureAlgorithmRSA},
				},
			},
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

		if len(c.localSRTPProtectionProfiles) > 0 {
			extensions = append(extensions, &extensionUseSRTP{
				protectionProfiles: c.localSRTPProtectionProfiles,
			})
		}

		if c.extendedMasterSecret == RequestExtendedMasterSecret ||
			c.extendedMasterSecret == RequireExtendedMasterSecret {
			extensions = append(extensions, &extensionUseExtendedMasterSecret{
				supported: true,
			})
		}

		if err := c.bufferPacket(&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(c.handshakeMessageSequence),
					},
					handshakeMessage: &handshakeMessageClientHello{
						version:            protocolVersion1_2,
						cookie:             c.cookie,
						random:             c.state.localRandom,
						cipherSuites:       c.localCipherSuites,
						compressionMethods: defaultCompressionMethods,
						extensions:         extensions,
					}},
			},
		}); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}

		if err := c.flushPacketBuffer(); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}
	case flight5:
		// TODO: Better way to end handshake
		if c.getRemoteEpoch() != 0 && c.getLocalEpoch() == 1 {
			// Handshake is done
			return true, nil, nil
		}

		messageSequence := c.handshakeMessageSequence
		if c.remoteRequestedCertificate {
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
		}

		clientKeyExchange := &handshakeMessageClientKeyExchange{}
		if c.localPSKCallback == nil {
			clientKeyExchange.publicKey = c.localKeypair.publicKey
		} else {
			clientKeyExchange.identityHint = c.localPSKIdentityHint
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
					handshakeMessage: clientKeyExchange,
				},
			},
		}); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}

		messageSequence++

		serverKeyExchangeData := c.handshakeCache.pullAndMerge(
			handshakeCachePullRule{handshakeTypeServerKeyExchange, false},
		)

		serverKeyExchange := &handshakeMessageServerKeyExchange{}

		// handshakeMessageServerKeyExchange is optional for PSK
		if len(serverKeyExchangeData) == 0 {
			alertPtr, err := handleServerKeyExchange(c, &handshakeMessageServerKeyExchange{})
			if err != nil {
				return false, alertPtr, err
			}
		} else {
			rawHandshake := &handshake{}
			err := rawHandshake.Unmarshal(serverKeyExchangeData)
			if err != nil {
				return false, &alert{alertLevelFatal, alertUnexpectedMessage}, err
			}

			switch h := rawHandshake.handshakeMessage.(type) {
			case *handshakeMessageServerKeyExchange:
				serverKeyExchange = h
			default:
				return false, &alert{alertLevelFatal, alertUnexpectedMessage}, errInvalidContentType
			}
		}

		if alertPtr, err := initalizeCipherSuite(c, serverKeyExchange); err != nil {
			return false, alertPtr, err
		}

		// If the client has sent a certificate with signing ability, a digitally-signed
		// CertificateVerify message is sent to explicitly verify possession of the
		// private key in the certificate.
		if c.remoteRequestedCertificate && len(c.localCertificates) > 0 {
			if len(c.localCertificatesVerify) == 0 {
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
				//TODO: choose right certficate by CAs provided in Certificate Request.
				certVerify, err := generateCertificateVerify(plainText, c.localCertificates[0].PrivateKey)
				if err != nil {
					return false, &alert{alertLevelFatal, alertInternalError}, err
				}
				c.localCertificatesVerify = certVerify
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
						handshakeMessage: &handshakeMessageCertificateVerify{
							hashAlgorithm:      hashAlgorithmSHA256,
							signatureAlgorithm: signatureAlgorithmECDSA,
							signature:          c.localCertificatesVerify,
						}},
				},
			}); err != nil {
				return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
			}

			messageSequence++
		}

		if err := c.flushPacketBuffer(); err != nil {
			return false, &alert{alertLevelFatal, alertHandshakeFailure}, err
		}

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
			)

			var err error
			c.localVerifyData, err = prfVerifyDataClient(c.state.masterSecret, plainText, c.state.cipherSuite.hashFunc())
			if err != nil {
				return false, &alert{alertLevelFatal, alertInternalError}, err
			}
		}

		// TODO: Fix hard-coded epoch, taking retransmitting into account.
		if err := c.bufferPacket(&packet{
			record: &recordLayer{
				recordLayerHeader: recordLayerHeader{
					epoch:           1,
					protocolVersion: protocolVersion1_2,
				},
				content: &handshake{
					handshakeHeader: handshakeHeader{
						messageSequence: uint16(messageSequence),
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
	default:
		return false, &alert{alertLevelFatal, alertUnexpectedMessage}, fmt.Errorf("unhandled flight %s", c.currFlight.get())
	}
	return false, nil, nil
}
