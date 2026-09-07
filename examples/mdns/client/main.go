// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Command client performs a DTLS handshake with the mDNS demo server.
package main

import (
	"context"
	"log"

	"github.com/pion/dtls/v3/examples/mdns/internal/mdnsdemo"
)

func main() {
	if err := mdnsdemo.RunClient(context.Background()); err != nil {
		log.Fatal(err)
	}
}
