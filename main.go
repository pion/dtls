package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	startListener()
}

func startListener() {
	pc, err := net.ListenPacket("udp", "127.0.0.1:4444")
	if err != nil {
		log.Fatal(err)
	}
	defer pc.Close()

	buffer := make([]byte, 8192)
	for {
		i, _, err := pc.ReadFrom(buffer)
		if i == 0 || err != nil {
			panic(fmt.Sprintf("%d %s", i, err.Error()))
		}
		pkts, err := decodeUDPPacket(buffer[:i])
		if err != nil {
			panic(err)
		}
		fmt.Println(pkts)
	}
}
