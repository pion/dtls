package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/sean-der/dtls/pkg/dtls"
)

const bufSize = 8192

func main() {
	addr := flag.String("address", ":44444", "server address")
	flag.Parse()

	// Listening on TCP since ice.Conn will also act like a stream based conn
	// while UDP acts like a packet based conn
	// We can figure out DTLS over UDP if we want to make the package stand-alone.
	baseListener, err := net.Listen("tcp", *addr)
	check(err)
	defer baseListener.Close()

	baseConn, err := baseListener.Accept()
	check(err)
	defer baseConn.Close()

	listener, err := dtls.ListenConn(baseConn)
	check(err)
	defer listener.Close()

	conn, err := listener.Accept()
	check(err)
	defer conn.Close()

	msg := "Hello world!"
	_, err = conn.Write([]byte(msg))
	check(err)

	fmt.Printf("Sent message: %s\n", msg)

	b := make([]byte, bufSize)
	n, err := conn.Read(b)
	check(err)

	fmt.Printf("Got message: %s\n", string(b[:n]))
}

// func assertLengthAndError(i int, err error) {
// 	if i == 0 || err != nil {
// 		panic(fmt.Sprintf("%d %s", i, err.Error()))
// 	}
// }

func check(err error) {
	if err != nil {
		panic(err)
	}
}
