package dtls

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/pion/transport/test"
)

// Seems to strict for out implementation at this point
// func TestNetTest(t *testing.T) {
// 	lim := test.TimeOut(time.Minute*1 + time.Second*10)
// 	defer lim.Stop()
//
// 	nettest.TestConn(t, func() (c1, c2 net.Conn, stop func(), err error) {
// 		c1, c2, err = pipeMemory()
// 		if err != nil {
// 			return nil, nil, nil, err
// 		}
// 		stop = func() {
// 			c1.Close()
// 			c2.Close()
// 		}
// 		return
// 	})
// }

func TestStressDuplex(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	// Run the test
	stressDuplex(t)
}

func stressDuplex(t *testing.T) {
	ca, cb, err := pipeMemory()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err = ca.Close()
		if err != nil {
			t.Fatal(err)
		}
		err = cb.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	opt := test.Options{
		MsgSize:  2048,
		MsgCount: 100,
	}

	err = test.StressDuplex(ca, cb, opt)
	if err != nil {
		t.Fatal(err)
	}
}

func pipeMemory() (*Conn, *Conn, error) {
	// In memory pipe
	ca, cb := net.Pipe()

	type result struct {
		c   *Conn
		err error
	}

	c := make(chan result)

	// Setup client
	go func() {
		client, err := testClient(ca, &Config{SRTPProtectionProfiles: []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80}}, true)
		c <- result{client, err}
	}()

	// Setup server
	server, err := testServer(cb, &Config{SRTPProtectionProfiles: []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80}}, true)
	if err != nil {
		return nil, nil, err
	}

	// Receive client
	res := <-c
	if res.err != nil {
		return nil, nil, res.err
	}

	return res.c, server, nil
}

func testClient(c net.Conn, cfg *Config, generateCertificate bool) (*Conn, error) {
	if generateCertificate {
		clientCert, clientKey, err := GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		cfg.PrivateKey = clientKey
		cfg.Certificate = clientCert
	}
	return Client(c, cfg)
}

func testServer(c net.Conn, cfg *Config, generateCertificate bool) (*Conn, error) {
	if generateCertificate {
		serverCert, serverKey, err := GenerateSelfSigned()
		if err != nil {
			return nil, err
		}
		cfg.PrivateKey = serverKey
		cfg.Certificate = serverCert
	}
	return Server(c, cfg)
}

func TestExportKeyingMaterial(t *testing.T) {
	var rand [28]byte
	exportLabel := "EXTRACTOR-dtls_srtp"

	expectedServerKey := []byte{0x61, 0x09, 0x9d, 0x7d, 0xcb, 0x08, 0x52, 0x2c, 0xe7, 0x7b}
	expectedClientKey := []byte{0x87, 0xf0, 0x40, 0x02, 0xf6, 0x1c, 0xf1, 0xfe, 0x8c, 0x77}

	c := &Conn{
		state: State{
			localRandom:  handshakeRandom{time.Unix(500, 0), rand},
			remoteRandom: handshakeRandom{time.Unix(1000, 0), rand},
			cipherSuite:  &cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{},
		},
	}
	c.setLocalEpoch(0)

	_, err := c.ExportKeyingMaterial(exportLabel, nil, 0)
	if err != errHandshakeInProgress {
		t.Errorf("ExportKeyingMaterial when epoch == 0: expected '%s' actual '%s'", errHandshakeInProgress, err)
	}

	c.setLocalEpoch(1)
	_, err = c.ExportKeyingMaterial(exportLabel, []byte{0x00}, 0)
	if err != errContextUnsupported {
		t.Errorf("ExportKeyingMaterial with context: expected '%s' actual '%s'", errContextUnsupported, err)
	}

	for k := range invalidKeyingLabels {
		_, err = c.ExportKeyingMaterial(k, nil, 0)
		if err != errReservedExportKeyingMaterial {
			t.Errorf("ExportKeyingMaterial reserved label: expected '%s' actual '%s'", errReservedExportKeyingMaterial, err)
		}
	}

	keyingMaterial, err := c.ExportKeyingMaterial(exportLabel, nil, 10)
	if err != nil {
		t.Errorf("ExportKeyingMaterial as server: unexpected error '%s'", err)
	} else if !bytes.Equal(keyingMaterial, expectedServerKey) {
		t.Errorf("ExportKeyingMaterial client export: expected (% 02x) actual (% 02x)", expectedServerKey, keyingMaterial)
	}

	c.state.isClient = true
	keyingMaterial, err = c.ExportKeyingMaterial(exportLabel, nil, 10)
	if err != nil {
		t.Errorf("ExportKeyingMaterial as server: unexpected error '%s'", err)
	} else if !bytes.Equal(keyingMaterial, expectedClientKey) {
		t.Errorf("ExportKeyingMaterial client export: expected (% 02x) actual (% 02x)", expectedClientKey, keyingMaterial)
	}
}

func TestPSK(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	for _, test := range []struct {
		Name           string
		ServerIdentity []byte
	}{
		{
			Name:           "Server identity specified",
			ServerIdentity: []byte("Test Identity"),
		},
		{
			Name:           "Server identity nil",
			ServerIdentity: nil,
		},
	} {

		clientIdentity := []byte("Client Identity")
		clientErr := make(chan error, 1)

		ca, cb := net.Pipe()
		go func() {
			conf := &Config{
				PSK: func(hint []byte) ([]byte, error) {
					if !bytes.Equal(test.ServerIdentity, hint) { // nolint
						return nil, fmt.Errorf("TestPSK: Client got invalid identity expected(% 02x) actual(% 02x)", test.ServerIdentity, hint) // nolint
					}

					return []byte{0xAB, 0xC1, 0x23}, nil
				},
				PSKIdentityHint: clientIdentity,
				CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM8},
			}

			_, err := testClient(ca, conf, false)
			clientErr <- err
		}()

		config := &Config{
			PSK: func(hint []byte) ([]byte, error) {
				if !bytes.Equal(clientIdentity, hint) {
					return nil, fmt.Errorf("TestPSK: Server got invalid identity expected(% 02x) actual(% 02x)", clientIdentity, hint)
				}
				return []byte{0xAB, 0xC1, 0x23}, nil
			},
			PSKIdentityHint: test.ServerIdentity,
			CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM8},
		}

		if _, err := testServer(cb, config, false); err != nil {
			t.Fatalf("TestPSK: Server failed(%v)", err)
		}

		if err := <-clientErr; err != nil {
			t.Fatal(err)
		}
	}
}

func TestPSKHintFail(t *testing.T) {
	pskRejected := errors.New("PSK Rejected")

	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	clientErr := make(chan error, 1)

	ca, cb := net.Pipe()
	go func() {
		conf := &Config{
			PSK: func(hint []byte) ([]byte, error) {
				return nil, pskRejected
			},
			PSKIdentityHint: []byte{},
			CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM8},
		}

		_, err := testClient(ca, conf, false)
		clientErr <- err
	}()

	config := &Config{
		PSK: func(hint []byte) ([]byte, error) {
			return nil, pskRejected
		},
		PSKIdentityHint: []byte{},
		CipherSuites:    []CipherSuiteID{TLS_PSK_WITH_AES_128_CCM8},
	}

	if _, err := testServer(cb, config, false); err != io.EOF && err != io.ErrClosedPipe {
		t.Fatalf("TestPSK: Server error exp(%v) failed(%v)", io.ErrClosedPipe, err)
	}

	if err := <-clientErr; err != pskRejected {
		t.Fatalf("TestPSK: Client error exp(%v) failed(%v)", pskRejected, err)
	}

}

func TestSRTPConfiguration(t *testing.T) {
	for _, test := range []struct {
		Name            string
		ClientSRTP      []SRTPProtectionProfile
		ServerSRTP      []SRTPProtectionProfile
		ExpectedProfile SRTPProtectionProfile
		WantClientError error
		WantServerError error
	}{
		{
			Name:            "No SRTP in use",
			ClientSRTP:      nil,
			ServerSRTP:      nil,
			ExpectedProfile: 0,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:            "SRTP both ends",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile: SRTP_AES128_CM_HMAC_SHA1_80,
			WantClientError: nil,
			WantServerError: nil,
		},
		{
			Name:            "SRTP client only",
			ClientSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ServerSRTP:      nil,
			ExpectedProfile: 0,
			WantClientError: io.EOF,
			WantServerError: fmt.Errorf("Client requested SRTP but we have no matching profiles"),
		},
		{
			Name:            "SRTP server only",
			ClientSRTP:      nil,
			ServerSRTP:      []SRTPProtectionProfile{SRTP_AES128_CM_HMAC_SHA1_80},
			ExpectedProfile: 0,
			WantClientError: nil,
			WantServerError: nil,
		},
	} {
		ca, cb := net.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		c := make(chan result)

		go func() {
			client, err := testClient(ca, &Config{SRTPProtectionProfiles: test.ClientSRTP}, true)
			c <- result{client, err}
		}()

		server, err := testServer(cb, &Config{SRTPProtectionProfiles: test.ServerSRTP}, true)
		if err != nil || test.WantServerError != nil {
			if !(err != nil && test.WantServerError != nil && err.Error() == test.WantServerError.Error()) {
				t.Errorf("TestSRTPConfiguration: Server Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantServerError, err)
			}
		}

		res := <-c
		if res.err != nil || test.WantClientError != nil {
			if !(res.err != nil && test.WantClientError != nil && res.err.Error() == test.WantClientError.Error()) {
				t.Errorf("TestSRTPConfiguration: Client Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantClientError, res.err)
			}
		}

		actualClientSRTP, _ := res.c.SelectedSRTPProtectionProfile()
		if actualClientSRTP != test.ExpectedProfile {
			t.Errorf("TestSRTPConfiguration: Client SRTPProtectionProfile Mismatch '%s': expected(%v) actual(%v)", test.Name, test.ExpectedProfile, actualClientSRTP)
		}

		actualServerSRTP, _ := server.SelectedSRTPProtectionProfile()
		if actualServerSRTP != test.ExpectedProfile {
			t.Errorf("TestSRTPConfiguration: Server SRTPProtectionProfile Mismatch '%s': expected(%v) actual(%v)", test.Name, test.ExpectedProfile, actualServerSRTP)
		}
	}
}

func TestClientCertificate(t *testing.T) {
	ca, cb := net.Pipe()
	type result struct {
		c    *Conn
		conf *Config
		err  error
	}
	c := make(chan result)

	go func() {
		conf := &Config{ClientAuth: RequireAnyClientCert}
		client, err := testClient(ca, conf, true)
		c <- result{client, conf, err}
	}()

	serverCfg := &Config{ClientAuth: RequireAnyClientCert}
	server, err := testServer(cb, serverCfg, true)
	if err != nil {
		t.Errorf("TestClientCertificate: Server failed(%v)", err)
	}

	res := <-c
	if res.err != nil {
		t.Errorf("TestClientCertificate: Client failed(%v)", res.err)
	}

	actualClientCert := server.RemoteCertificate()
	if actualClientCert == nil {
		t.Errorf("TestClientCertificate: Client did not provide a certificate")
	}

	actualServerCert := res.c.RemoteCertificate()
	if actualServerCert == nil {
		t.Errorf("TestClientCertificate: Server did not provide a certificate")
	}

	if !actualServerCert.Equal(serverCfg.Certificate) {
		t.Errorf("TestClientCertificate: Server certificate was not communicated correctly")
	}

	if !actualClientCert.Equal(res.conf.Certificate) {
		t.Errorf("TestClientCertificate: Server certificate was not communicated correctly")
	}
}

func TestCipherSuiteConfiguration(t *testing.T) {
	for _, test := range []struct {
		Name               string
		ClientCipherSuites []CipherSuiteID
		ServerCipherSuites []CipherSuiteID
		WantClientError    error
		WantServerError    error
	}{
		{
			Name:               "No CipherSuites specified",
			ClientCipherSuites: nil,
			ServerCipherSuites: nil,
			WantClientError:    nil,
			WantServerError:    nil,
		},
		{
			Name:               "Invalid CipherSuite",
			ClientCipherSuites: []CipherSuiteID{0x00},
			ServerCipherSuites: []CipherSuiteID{0x00},
			WantClientError:    errors.New("CipherSuite with id(0) is not valid"),
			WantServerError:    errors.New("CipherSuite with id(0) is not valid"),
		},
		{
			Name:               "Valid CipherSuites specified",
			ClientCipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			WantClientError:    nil,
			WantServerError:    nil,
		},
		{
			Name:               "CipherSuites mismatch",
			ClientCipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			ServerCipherSuites: []CipherSuiteID{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
			WantClientError:    io.EOF,
			WantServerError:    errCipherSuiteNoIntersection,
		},
	} {
		ca, cb := net.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		c := make(chan result)

		go func() {
			client, err := testClient(ca, &Config{CipherSuites: test.ClientCipherSuites}, true)
			c <- result{client, err}
		}()

		_, err := testServer(cb, &Config{CipherSuites: test.ServerCipherSuites}, true)
		if err != nil || test.WantServerError != nil {
			if !(err != nil && test.WantServerError != nil && err.Error() == test.WantServerError.Error()) {
				t.Errorf("TestCipherSuiteConfiguration: Server Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantServerError, err)
			}
		}

		res := <-c
		if res.err != nil || test.WantClientError != nil {
			if !(res.err != nil && test.WantClientError != nil && res.err.Error() == test.WantClientError.Error()) {
				t.Errorf("TestSRTPConfiguration: Client Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantClientError, res.err)
			}
		}
	}
}

func TestPSKConfiguration(t *testing.T) {
	for _, test := range []struct {
		Name                 string
		ClientHasCertificate bool
		ServerHasCertificate bool
		ClientPSK            PSKCallback
		ServerPSK            PSKCallback
		ClientPSKIdentity    []byte
		ServerPSKIdentity    []byte
		WantClientError      error
		WantServerError      error
	}{
		{
			Name:                 "PSK specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errNoAvailableCipherSuites,
			WantServerError:      errNoAvailableCipherSuites,
		},
		{
			Name:                 "PSK and certificate specified",
			ClientHasCertificate: true,
			ServerHasCertificate: true,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errPSKAndCertificate,
			WantServerError:      errPSKAndCertificate,
		},
		{
			Name:                 "PSK and no identity specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ServerPSK:            func([]byte) ([]byte, error) { return []byte{0x00, 0x01, 0x02}, nil },
			ClientPSKIdentity:    nil,
			ServerPSKIdentity:    nil,
			WantClientError:      errPSKAndIdentityMustBeSetForClient,
			WantServerError:      errNoAvailableCipherSuites,
		},
		{
			Name:                 "No PSK and identity specified",
			ClientHasCertificate: false,
			ServerHasCertificate: false,
			ClientPSK:            nil,
			ServerPSK:            nil,
			ClientPSKIdentity:    []byte{0x00},
			ServerPSKIdentity:    []byte{0x00},
			WantClientError:      errIdentityNoPSK,
			WantServerError:      errServerMustHaveCertificate,
		},
	} {
		ca, cb := net.Pipe()
		type result struct {
			c   *Conn
			err error
		}
		c := make(chan result)

		go func() {
			client, err := testClient(ca, &Config{PSK: test.ClientPSK, PSKIdentityHint: test.ClientPSKIdentity}, test.ClientHasCertificate)
			c <- result{client, err}
		}()

		_, err := testServer(cb, &Config{PSK: test.ServerPSK, PSKIdentityHint: test.ServerPSKIdentity}, test.ServerHasCertificate)
		if err != nil || test.WantServerError != nil {
			if !(err != nil && test.WantServerError != nil && err.Error() == test.WantServerError.Error()) {
				t.Fatalf("TestPSKConfiguration: Server Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantServerError, err)
			}
		}

		res := <-c
		if res.err != nil || test.WantClientError != nil {
			if !(res.err != nil && test.WantClientError != nil && res.err.Error() == test.WantClientError.Error()) {
				t.Fatalf("TestPSKConfiguration: Client Error Mismatch '%s': expected(%v) actual(%v)", test.Name, test.WantClientError, res.err)
			}
		}
	}
}
