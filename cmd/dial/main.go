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
	certificate, privateKey := cmd.GenerateCertificate()

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{certificate, privateKey}

	// Connect to a DTLS server
	dtlsConn, err := dtls.Dial("udp", addr, config)
	cmd.Check(err)
	defer dtlsConn.Close()

	fmt.Println("Connected")

	// Simulate a chat session
	cmd.Chat(dtlsConn)
}
