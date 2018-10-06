package main

import (
	"fmt"
	"log"
	"net"

	"github.com/sean-der/dtls/pkg/dtls"
)

var dstAddr net.Addr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

const bufSize = 8192

func main() {
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer udpConn.Close()

	dtlsConn, err := dtls.Start(true)
	if err != nil {
		log.Fatal(err)
	}
	defer dtlsConn.Close()

	go func() {
		buffer := make([]byte, bufSize)
		for {
			i, _, err := udpConn.ReadFrom(buffer)
			assertLengthAndError(i, err)

			i, err = dtlsConn.Write(buffer[:i])
			assertLengthAndError(i, err)
		}
	}()

	buffer := make([]byte, bufSize)
	for {
		i, err := dtlsConn.Read(buffer)
		assertLengthAndError(i, err)

		i, err = udpConn.WriteTo(buffer[:i], dstAddr)
		assertLengthAndError(i, err)
	}
}

func assertLengthAndError(i int, err error) {
	if i == 0 || err != nil {
		panic(fmt.Sprintf("%d %s", i, err.Error()))
	}
}
