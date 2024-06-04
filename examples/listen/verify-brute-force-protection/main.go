// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements an example DTLS server which verifies client certificates.
// It also implements a basic Brute Force Attack protection.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/examples/util"
)

func main() {
	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

	// Create parent context to cleanup handshaking connections on exit.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// ************ Variables used to implement a basic Brute Force Attack protection *************
	var attempts = make(map[string]int) // Map of attempts for each IP address.
	var attemptsMutex sync.Mutex        // Mutex for the map of attempts.
	var attemptsCleaner = time.Now()    // Time to be able to clean the map of attempts every X minutes.

	certificate, err := util.LoadKeyAndCertificate("examples/certificates/server.pem",
		"examples/certificates/server.pub.pem")
	util.Check(err)

	rootCertificate, err := util.LoadCertificate("examples/certificates/server.pub.pem")
	util.Check(err)
	certPool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
	util.Check(err)
	certPool.AddCert(cert)

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificates:         []tls.Certificate{certificate},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ClientAuth:           dtls.RequireAndVerifyClientCert,
		ClientCAs:            certPool,
		// Create timeout context for accepted connection.
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(ctx, 30*time.Second)
		},
		// This function will be called on each connection attempt.
		OnConnectionAttempt: func(addr net.Addr) error {
			// *************** Brute Force Attack protection ***************
			// Check if the IP address is in the map, and if the IP address has exceeded the limit
			attemptsMutex.Lock()
			defer attemptsMutex.Unlock()
			// Here I implement a time cleaner for the map of attempts, every 5 minutes I will
			// decrement by 1 the number of attempts for each IP address.
			if time.Now().After(attemptsCleaner.Add(time.Minute * 5)) {
				attemptsCleaner = time.Now()
				for k, v := range attempts {
					if v > 0 {
						attempts[k]--
					}
					if attempts[k] == 0 {
						delete(attempts, k)
					}
				}
			}
			// Check if the IP address is in the map, and the IP address has exceeded the limit (Brute Force Attack protection)
			attemptIP := addr.(*net.UDPAddr).IP.String()
			if attempts[attemptIP] > 10 {
				return fmt.Errorf("too many attempts from this IP address")
			}
			// Here I increment the number of attempts for this IP address (Brute Force Attack protection)
			attempts[attemptIP]++
			// *************** END Brute Force Attack protection END ***************
			return nil
		},
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

			// *************** Brute Force Attack protection ***************
			// Here I decrease the number of attempts for this IP address
			attemptsMutex.Lock()
			attemptIP := conn.(*dtls.Conn).RemoteAddr().(*net.UDPAddr).IP.String()
			attempts[attemptIP]--
			// If the number of attempts for this IP address is 0, I delete the IP address from the map
			if attempts[attemptIP] == 0 {
				delete(attempts, attemptIP)
			}
			attemptsMutex.Unlock()
			// *************** END Brute Force Attack protection END ***************

			// Register the connection with the chat hub
			hub.Register(conn)
		}
	}()

	// Start chatting
	hub.Chat()
}
