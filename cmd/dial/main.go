package main

import (
	"fmt"
	"net"

	"github.com/pions/dtls/cmd"
	"github.com/pions/dtls/pkg/dtls"
)

func main() {
	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

	// Generate a certificate and private key to secure the connection
	certificate, privateKey, genErr := dtls.GenerateSelfSigned()
	cmd.Check(genErr)

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{Certificate: certificate, PrivateKey: privateKey}

	// Connect to a DTLS server
	dtlsConn, err := dtls.Dial("udp", addr, config)
	cmd.Check(err)
	defer func() {
		cmd.Check(dtlsConn.Close())
	}()

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	cmd.Chat(dtlsConn)
}
