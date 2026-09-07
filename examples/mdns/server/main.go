// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Command server accepts a DTLS handshake from the mDNS demo client.
package main

import (
	"context"
	"log"

	"github.com/pion/dtls/v3/examples/mdns/internal/mdnsdemo"
)

func main() {
	if err := mdnsdemo.RunServer(context.Background()); err != nil {
		log.Fatal(err)
	}
}
