package main

import (
	"fmt"
	"net"

	"github.com/pions/dtls/pkg/dtls"
	"github.com/pions/dtls/pkg/ice"
)

const bufSize = 8192

func main() {
	a, _ := ice.Listen("127.0.0.1:4444", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555})

	dtlsConn, err := dtls.Server(a)
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
