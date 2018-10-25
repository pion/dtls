package main

import (
	"fmt"
	"net"

	"github.com/pions/dtls/pkg/dtls"
	"github.com/pions/dtls/pkg/ice"
)

const bufSize = 8192

func main() {
	a, _ := ice.Listen("127.0.0.1:5555", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444})

	dtlsConn, err := dtls.Dial(a)
	check(err)
	defer dtlsConn.Close()

	b := make([]byte, bufSize)
	for {
		n, err := dtlsConn.Read(b)
		check(err)
		fmt.Printf("Got message: %s\n", string(b[:n]))
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
