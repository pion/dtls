package main

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/dtls"
	"github.com/pion/dtls/examples/util"
)

func main() {
	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			fmt.Printf("Server's hint: %s \n", hint)
			return []byte{0xAB, 0xC1, 0x23}, nil
		},
		PSKIdentityHint:      []byte("Pion DTLS Server"),
		CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ConnectTimeout:       dtls.ConnectTimeoutOption(30 * time.Second),
	}

	// Connect to a DTLS server
	dtlsConn, err := dtls.Dial("udp", addr, config)
	util.Check(err)
	defer func() {
		util.Check(dtlsConn.Close())
	}()

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	util.Chat(dtlsConn)
}
