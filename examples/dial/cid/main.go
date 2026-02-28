// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements an example DTLS client using a pre-shared key.
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/examples/util"
)

func main() {
	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Connect to a DTLS server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.DialWithOptions("udp", addr,
		dtls.WithPSK(func(hint []byte) ([]byte, error) {
			fmt.Printf("Server's hint: %s \n", hint)

			return []byte{0xAB, 0xC1, 0x23}, nil
		}),
		dtls.WithPSKIdentityHint([]byte("Pion DTLS Client")),
		dtls.WithCipherSuites(dtls.TLS_PSK_WITH_AES_128_CCM_8),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithConnectionIDGenerator(dtls.OnlySendCIDGenerator()),
	)
	util.Check(err)
	defer func() {
		util.Check(dtlsConn.Close())
	}()

	if err := dtlsConn.HandshakeContext(ctx); err != nil {
		fmt.Printf("Failed to handshake with server: %v\n", err)

		return
	}

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	util.Chat(dtlsConn)
}
