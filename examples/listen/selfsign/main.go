// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements an example DTLS server using self-signed certificates.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/examples/util"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

func main() {
	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

	// Generate a certificate and private key to secure the connection
	certificate, genErr := selfsign.GenerateSelfSigned()
	util.Check(genErr)

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificates:         []tls.Certificate{certificate},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	// Connect to a DTLS server
	listener, err := dtls.Listen("udp", addr, config)
	util.Check(err)
	defer func() {
		util.Check(listener.Close())
	}()

	fmt.Println("Listening")

	// Simulate a chat session
	hub := util.NewHub()

	go func() {
		for {
			// Wait for a connection.
			conn, err := listener.Accept()
			util.Check(err)
			// defer conn.Close() // TODO: graceful shutdown

			// `conn` is of type `net.Conn` but may be casted to `dtls.Conn`
			// using `dtlsConn := conn.(*dtls.Conn)` in order to to expose
			// functions like `ConnectionState` etc.

			// Perform the handshake with a 30-second timeout
			ctx, cancel := context.WithTimeout(context.Background(), 30)
			dtlsConn, ok := conn.(*dtls.Conn)
			if ok {
				util.Check(dtlsConn.HandshakeContext(ctx))
			}
			cancel()

			// Register the connection with the chat hub
			if err == nil {
				hub.Register(conn)
			}
		}
	}()

	// Start chatting
	hub.Chat()
}
