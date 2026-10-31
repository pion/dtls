// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements an example DTLS client using a pre-shared key.
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

	// Connect to a DTLS server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.Dial("udp", addr,
		dtls.WithPSK(func() ([]dtls.PSK, error) {
			return []dtls.PSK{{Identity: []byte("Pion DTLS Client"), Key: []byte{0xAB, 0xC1, 0x23}}}, nil
		}, nil),
		dtls.WithMinVersion(version),
		dtls.WithMaxVersion(version),
		dtls.WithCipherSuites(cipherSuite),
		// EMS applies only to DTLS 1.2, binding the master secret to the handshake transcript.
		// DTLS 1.3 binds traffic secrets to the transcript through its key schedule without EMS.
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithConnectionID(dtls.OnlySendCIDGenerator(), dtls.CIDPathMigrationUnsafe),
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
