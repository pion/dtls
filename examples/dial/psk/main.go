// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements an example DTLS client using a pre-shared key.
package main

import (
	"context"
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

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// *************** Variables only used to implement a basic Brute Force Attack protection ***************
	var attempts = make(map[string]int) // Map of attempts for each IP address
	var attemptsMutex sync.Mutex        // Mutex for the map of attempts
	var attemptsCleaner = time.Now()    // Time to be able to clean the map of attempts every X minutes

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		PSK: func(hint []byte, addr net.Addr) ([]byte, error) {
			fmt.Printf("Server's hint: %s \n", hint)
			// *************** Brute Force Attack protection ***************
			// Check if the IP address is in the map, and the IP address has exceeded the limit
			attemptsMutex.Lock()
			defer attemptsMutex.Unlock()
			// Here I implement a time cleaner for the map of attempts, every 5 minutes I will decrement by 1 the number of attempts for each IP address
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
			if attempts[addr.(*net.UDPAddr).IP.String()] > 5 {
				return nil, fmt.Errorf("too many attempts from this IP address")
			}
			// Here I increment the number of attempts for this IP address (Brute Force Attack protection)
			attempts[addr.(*net.UDPAddr).IP.String()]++
			// *************** END Brute Force Attack protection END ***************
			// I return the PSK
			return []byte{0xAB, 0xC1, 0x23}, nil
		},
		PSKIdentityHint:      []byte("Pion DTLS Client"),
		CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	// Connect to a DTLS server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dtlsConn, err := dtls.DialWithContext(ctx, "udp", addr, config)
	util.Check(err)
	defer func() {
		util.Check(dtlsConn.Close())
	}()

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	util.Chat(dtlsConn)
}
