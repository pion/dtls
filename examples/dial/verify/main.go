// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a DTLS client using a client certificate.
package main

import (
	"context"
	"crypto/x509"
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

	certificate, err := util.LoadKeyAndCertificate("examples/certificates/client.pem",
		"examples/certificates/client.pub.pem")
	util.Check(err)

	rootCertificate, err := util.LoadCertificate("examples/certificates/server.pub.pem")
	util.Check(err)
	certPool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
	util.Check(err)
	certPool.AddCert(cert)

	// Connect to a DTLS server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.DialWithOptions("udp", addr,
		dtls.WithCertificates(certificate),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithRootCAs(certPool),
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
