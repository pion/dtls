// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/pion/dtls/v3/internal/ciphersuite"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol/alert"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/logging"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type flight4TestMockFlightConn struct{}

func (f *flight4TestMockFlightConn) notify(context.Context, alert.Level, alert.Description) error {
	return nil
}
func (f *flight4TestMockFlightConn) writePackets(context.Context, []*packet) error { return nil }
func (f *flight4TestMockFlightConn) recvHandshake() <-chan recvHandshakeState      { return nil }
func (f *flight4TestMockFlightConn) setLocalEpoch(uint16)                          {}
func (f *flight4TestMockFlightConn) handleQueuedPackets(context.Context) error     { return nil }
func (f *flight4TestMockFlightConn) sessionKey() []byte                            { return nil }

type flight4TestMockCipherSuite struct {
	ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256

	t *testing.T
}

func (f *flight4TestMockCipherSuite) IsInitialized() bool {
	assert.Fail(f.t, "IsInitialized called with Certificate but not CertificateVerify")

	return true
}

// Assert that if a Client sends a certificate they
// must also send a CertificateVerify message.
// The flight4handler must not interact with the CipherSuite
// if the CertificateVerify is missing.
func TestFlight4_Process_CertificateVerify(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	mockConn := &flight4TestMockFlightConn{}
	state := &State{
		cipherSuite: &flight4TestMockCipherSuite{t: t},
	}
	cache := newHandshakeCache()
	cfg := &handshakeConfig{}

	rawCertificate := []byte{
		0x0b, 0x00, 0x01, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x9b, 0x00, 0x01, 0x98, 0x00, 0x01, 0x95, 0x30, 0x82,
		0x01, 0x91, 0x30, 0x82, 0x01, 0x38, 0xa0, 0x03, 0x02, 0x01,
		0x02, 0x02, 0x11, 0x01, 0x65, 0x03, 0x3f, 0x4d, 0x0b, 0x9a,
		0x62, 0x91, 0xdb, 0x4d, 0x28, 0x2c, 0x1f, 0xd6, 0x73, 0x32,
		0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
		0x03, 0x02, 0x30, 0x00, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x32,
		0x30, 0x35, 0x31, 0x35, 0x31, 0x38, 0x34, 0x33, 0x35, 0x35,
		0x5a, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x36, 0x31, 0x35, 0x31,
		0x38, 0x34, 0x33, 0x35, 0x35, 0x5a, 0x30, 0x00, 0x30, 0x59,
		0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
		0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
		0x07, 0x03, 0x42, 0x00, 0x04, 0xc3, 0xb7, 0x13, 0x1a, 0x0a,
		0xfc, 0xd0, 0x82, 0xf8, 0x94, 0x5e, 0xc0, 0x77, 0x07, 0x81,
		0x28, 0xc9, 0xcb, 0x08, 0x84, 0x50, 0x6b, 0xf0, 0x22, 0xe8,
		0x79, 0xb9, 0x15, 0x33, 0xc4, 0x56, 0xa1, 0xd3, 0x1b, 0x24,
		0xe3, 0x61, 0xbd, 0x4d, 0x65, 0x80, 0x6b, 0x5d, 0x96, 0x48,
		0xa2, 0x44, 0x9e, 0xce, 0xe8, 0x65, 0xd6, 0x3c, 0xe0, 0x9b,
		0x6b, 0xa1, 0x36, 0x34, 0xb2, 0x39, 0xe2, 0x03, 0x00, 0xa3,
		0x81, 0x92, 0x30, 0x81, 0x8f, 0x30, 0x0e, 0x06, 0x03, 0x55,
		0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x02,
		0xa4, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16,
		0x30, 0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
		0x03, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
		0x03, 0x01, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
		0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
		0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14,
		0xb1, 0x1a, 0xe3, 0xeb, 0x6f, 0x7c, 0xc3, 0x8f, 0xba, 0x6f,
		0x1c, 0xe8, 0xf0, 0x23, 0x08, 0x50, 0x8d, 0x3c, 0xea, 0x31,
		0x30, 0x2e, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff,
		0x04, 0x24, 0x30, 0x22, 0x82, 0x20, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x0a,
		0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
		0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x06, 0x31, 0x43,
		0xac, 0x03, 0x45, 0x79, 0x3c, 0xd7, 0x5f, 0x6e, 0x6a, 0xf8,
		0x0e, 0xfd, 0x35, 0x49, 0xee, 0x1b, 0xbc, 0x47, 0xce, 0xe3,
		0x39, 0xec, 0xe4, 0x62, 0xe1, 0x30, 0x1a, 0xa1, 0x89, 0x02,
		0x20, 0x35, 0xcd, 0x7a, 0x15, 0x68, 0x09, 0x50, 0x49, 0x9e,
		0x3e, 0x05, 0xd7, 0xc2, 0x69, 0x3f, 0x9c, 0x0c, 0x98, 0x92,
		0x65, 0xec, 0xae, 0x44, 0xfe, 0xe5, 0x68, 0xb8, 0x09, 0x78,
		0x7f, 0x6b, 0x77,
	}

	rawClientKeyExchange := []byte{
		0x10, 0x00, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x21, 0x20, 0x96, 0xed, 0x0c, 0xee, 0xf3, 0x11, 0xb1,
		0x9d, 0x8b, 0x1c, 0x02, 0x7f, 0x06, 0x7c, 0x57, 0x7a, 0x14,
		0xa6, 0x41, 0xde, 0x63, 0x57, 0x9e, 0xcd, 0x34, 0x54, 0xba,
		0x37, 0x4d, 0x34, 0x15, 0x18,
	}

	assert.NoError(t, cache.push(rawCertificate, 0, 0, handshake.TypeCertificate, true))
	assert.NoError(t, cache.push(rawClientKeyExchange, 0, 1, handshake.TypeClientKeyExchange, true))

	_, _, err := flight4Parse(context.TODO(), mockConn, state, cache, cfg)
	assert.NoError(t, err)
}

func TestFlight4_CertificateRequestHook(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(5 * time.Second)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	localKeypair, err := elliptic.GenerateKeypair(elliptic.P256)
	assert.NoError(t, err)

	mockConn := &flight4TestMockFlightConn{}
	state := &State{
		cipherSuite:  &flight4TestMockCipherSuite{t: t},
		localKeypair: localKeypair,
	}

	cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
	assert.NoError(t, err)

	cfg := &handshakeConfig{
		localCertificates:     []tls.Certificate{cert},
		localSignatureSchemes: signaturehash.Algorithms(),
		clientAuth:            1,
		certificateRequestMessageHook: func(mcr handshake.MessageCertificateRequest) handshake.Message {
			mcr.SignatureHashAlgorithms = []signaturehash.Algorithm{}

			return &mcr
		},
	}

	pkts, _, err := flight4Generate(mockConn, state, nil, cfg)
	assert.NoError(t, err)

	for _, p := range pkts {
		if h, ok := p.record.Content.(*handshake.Handshake); ok { //nolint:nestif
			if h.Message.Type() == handshake.TypeCertificateRequest {
				mcr := &handshake.MessageCertificateRequest{}
				msg, err := h.Message.Marshal()
				assert.NoError(t, err)
				assert.NoError(t, mcr.Unmarshal(msg))
				if len(mcr.SignatureHashAlgorithms) == 0 {
					return
				}
			}
		}
	}
	assert.Fail(t, "hook failed to modify SignatureHashAlgorithms")
}

func TestFlight4ProcessesClientFlightOnce(t *testing.T) {
	for _, clientAuth := range []ClientAuthType{RequireAnyClientCert, RequireAndVerifyClientCert} {
		t.Run(fmt.Sprint(clientAuth), func(t *testing.T) {
			for _, finishedCase := range []struct {
				name   string
				mutate func([]byte) []byte
			}{
				{"valid", nil},
				{"corrupt", func(data []byte) []byte {
					data[0] ^= 1

					return data
				}},
				{"empty", func([]byte) []byte { return nil }},
				{"short", func(data []byte) []byte { return data[:len(data)-1] }},
				{"long", func(data []byte) []byte { return append(data, 0) }},
			} {
				t.Run(finishedCase.name, func(t *testing.T) {
					certificate, err := selfsign.GenerateSelfSigned()
					require.NoError(t, err)
					roots := x509.NewCertPool()
					parsed, err := x509.ParseCertificate(certificate.Certificate[0])
					require.NoError(t, err)
					roots.AddCert(parsed)
					keypair, err := elliptic.GenerateKeypair(elliptic.P256)
					require.NoError(t, err)
					state := &State{cipherSuite: &ciphersuite.TLSEcdheEcdsaWithAes128GcmSha256{}, localKeypair: keypair}
					cache := newHandshakeCache()
					calls := 0
					cfg := &handshakeConfig{
						clientAuth:            clientAuth,
						clientCAs:             roots,
						localSignatureSchemes: signaturehash.Algorithms(),
						verifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
							calls++

							return nil
						},
					}
					certRaw := cacheFlight4TestMessage(t, cache, 0, 0, &handshake.MessageCertificate{
						Certificate: certificate.Certificate,
					})
					keyRaw := cacheFlight4TestMessage(t, cache, 0, 1, &handshake.MessageClientKeyExchange{
						PublicKey: keypair.PublicKey,
					})
					conn := &flight4TestMockFlightConn{}
					flight, alertPtr, err := flight4Parse(context.Background(), conn, state, cache, cfg)
					require.NoError(t, err)
					require.Nil(t, alertPtr)
					require.Zero(t, flight)
					require.Zero(t, calls)
					originalCert := &state.PeerCertificates[0][0]
					for range 100 {
						flight, alertPtr, err = flight4Parse(context.Background(), conn, state, cache, cfg)
						require.NoError(t, err)
						require.Nil(t, alertPtr)
						require.Zero(t, flight)
						require.Same(t, originalCert, &state.PeerCertificates[0][0], "certificate must not be decoded again")
					}
					require.False(t, state.cipherSuite.IsInitialized())
					signer, ok := certificate.PrivateKey.(crypto.Signer)
					require.True(t, ok)
					transcript := append([]byte{}, certRaw...)
					transcript = append(transcript, keyRaw...)
					sig, err := generateCertificateVerify(transcript, signer, hash.SHA256, signature.ECDSA)
					require.NoError(t, err)
					verifyRaw := cacheFlight4TestMessage(t, cache, 0, 2, &handshake.MessageCertificateVerify{
						HashAlgorithm: hash.SHA256, SignatureAlgorithm: signature.ECDSA, Signature: sig,
					})
					for range 100 {
						flight, alertPtr, err = flight4Parse(context.Background(), conn, state, cache, cfg)
						require.NoError(t, err)
						require.Nil(t, alertPtr)
						require.Zero(t, flight)
						require.Equal(t, 1, calls)
						require.Same(t, originalCert, &state.PeerCertificates[0][0])
					}
					require.True(t, state.cipherSuite.IsInitialized())
					transcript = append(transcript, verifyRaw...)
					verifyData, err := prf.VerifyDataClient(state.masterSecret, transcript, state.cipherSuite.HashFunc())
					require.NoError(t, err)
					if finishedCase.mutate != nil {
						verifyData = finishedCase.mutate(verifyData)
					}
					cacheFlight4TestMessage(t, cache, 1, 3, &handshake.MessageFinished{VerifyData: verifyData})
					flight, alertPtr, err = flight4Parse(context.Background(), conn, state, cache, cfg)
					if finishedCase.mutate != nil {
						require.ErrorIs(t, err, errVerifyDataMismatch)
						require.Equal(t, &alert.Alert{Level: alert.Fatal, Description: alert.HandshakeFailure}, alertPtr)
						require.Zero(t, flight)
						require.Equal(t, 3, state.handshakeRecvSequence)

						return
					}
					require.NoError(t, err)
					require.Nil(t, alertPtr)
					require.Equal(t, flight6, flight)
					require.Equal(t, 1, calls)
				})
			}
		})
	}
}

func cacheFlight4TestMessage(t *testing.T, cache *handshakeCache, epoch, seq uint16, message handshake.Message) []byte {
	t.Helper()
	packet := &handshake.Handshake{Header: handshake.Header{MessageSequence: seq}, Message: message}
	raw, err := packet.Marshal()
	require.NoError(t, err)
	require.NoError(t, cache.push(raw, epoch, seq, message.Type(), true))

	return raw
}

type flight4CountingSessionStore struct {
	SessionStore
	calls int
}

func (s *flight4CountingSessionStore) Set([]byte, Session) error {
	s.calls++

	return nil
}

func TestFlight4StoresSessionOnce(t *testing.T) {
	store := &flight4CountingSessionStore{}
	pskCalls := 0
	cfg := &handshakeConfig{
		sessionStore: store,
		log:          logging.NewDefaultLoggerFactory().NewLogger("dtls"),
		localPSKCallback: func([]byte) ([]byte, error) {
			pskCalls++

			return []byte("test key"), nil
		},
	}
	state := &State{cipherSuite: &ciphersuite.TLSPskWithAes128GcmSha256{}, SessionID: []byte("session")}
	cache := newHandshakeCache()
	cacheFlight4TestMessage(t, cache, 0, 0, &handshake.MessageClientKeyExchange{IdentityHint: []byte("peer")})
	for range 100 {
		flight, alertPtr, err := flight4Parse(context.Background(), &flight4TestMockFlightConn{}, state, cache, cfg)
		require.NoError(t, err)
		require.Nil(t, alertPtr)
		require.Zero(t, flight)
	}
	require.Equal(t, 1, store.calls)
	require.Equal(t, 1, pskCalls)
}
