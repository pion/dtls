package main

import (
	"fmt"
	"net"

	"github.com/pions/dtls/cmd"
	"github.com/pions/dtls/internal/ice"
	"github.com/pions/dtls/pkg/dtls"
)

func main() {
	// Simulate an underlying connection
	a, _ := ice.Listen("127.0.0.1:5555", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444})

	// Generate a certificate and private key to secure the connection
	certificate, privateKey := cmd.GenerateCertificate()

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{certificate, privateKey}

	// Start a DTLS client over the existing connection
	dtlsConn, err := dtls.Client(a, config)
	cmd.Check(err)
	defer dtlsConn.Close()

	fmt.Println("Connected")

	// Simulate a chat session
	cmd.Chat(dtlsConn)
}
