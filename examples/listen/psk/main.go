// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a DTLS server using a pre-shared key.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/dtls/v4/examples/util"
	"github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/protocol"
)

func main() {
	dtls12 := flag.Bool("dtls12", false, "use DTLS 1.2 instead of DTLS 1.3")
	flag.Parse()

	version := protocol.Version1_3
	cipherSuite := ciphersuite.TLS_AES_128_GCM_SHA256
	if *dtls12 {
		version = protocol.Version1_2
		cipherSuite = ciphersuite.TLS_PSK_WITH_AES_128_CCM_8
	}

	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	listener, err := dtls.ListenAddr("udp", addr,
		dtls.WithPSK(nil, func(identities [][]byte) (*dtls.PSK, error) {
			fmt.Printf("Client's identity: %s \n", identities[0])

			return &dtls.PSK{Identity: identities[0], Key: []byte{0xAB, 0xC1, 0x23}}, nil
		}),
		dtls.WithMinVersion(version),
		dtls.WithMaxVersion(version),
		dtls.WithCipherSuites(cipherSuite),
		// EMS applies only to DTLS 1.2, binding the master secret to the handshake transcript.
		// DTLS 1.3 binds traffic secrets to the transcript through its key schedule without EMS.
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
	)
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
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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
