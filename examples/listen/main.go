package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/pions/dtls"
	"github.com/pions/dtls/examples/util"
)

func main() {
	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

	// Generate a certificate and private key to secure the connection
	certificate, privateKey, genErr := dtls.GenerateSelfSigned()
	util.Check(genErr)

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{Certificate: certificate, PrivateKey: privateKey}

	// Connect to a DTLS server
	listener, err := dtls.Listen("udp", addr, config)
	util.Check(err)
	defer func() {
		util.Check(listener.Close())
	}()

	fmt.Println("Listening")

	// Simulate a chat session
	hub := newHub()

	go func() {
		for {
			// Wait for a connection.
			conn, err := listener.Accept()
			util.Check(err)
			// defer conn.Close() // TODO: graceful shutdown

			// Register the connection with the chat hub
			hub.register(conn)
		}
	}()

	// Start chatting
	hub.chat()
}

const bufSize = 8192

// hub is a helper to handle one to many chat
type hub struct {
	conns map[string]net.Conn
	lock  sync.RWMutex
}

func newHub() *hub {
	return &hub{conns: make(map[string]net.Conn)}
}

func (h *hub) register(conn net.Conn) {
	fmt.Printf("Connected to %s\n", conn.RemoteAddr())
	h.lock.Lock()
	defer h.lock.Unlock()

	h.conns[conn.RemoteAddr().String()] = conn

	go h.readLoop(conn)
}

func (h *hub) readLoop(conn net.Conn) {
	b := make([]byte, bufSize)
	for {
		n, err := conn.Read(b)
		if err != nil {
			h.unregister(conn)
			return
		}
		fmt.Printf("Got message: %s\n", string(b[:n]))
	}
}

func (h *hub) unregister(conn net.Conn) {
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.conns, conn.RemoteAddr().String())
	err := conn.Close()
	if err != nil {
		fmt.Println("Failed to disconnect", conn.RemoteAddr(), err)
	} else {
		fmt.Println("Disconnected ", conn.RemoteAddr())
	}
}

func (h *hub) broadcast(msg []byte) {
	h.lock.RLock()
	defer h.lock.RUnlock()
	for _, conn := range h.conns {
		_, err := conn.Write(msg)
		if err != nil {
			fmt.Printf("Failed to write message to %s: %v\n", conn.RemoteAddr(), err)
		}
	}
}

func (h *hub) chat() {
	reader := bufio.NewReader(os.Stdin)
	for {
		msg, err := reader.ReadString('\n')
		util.Check(err)
		if strings.TrimSpace(msg) == "exit" {
			return
		}
		h.broadcast([]byte(msg))
	}
}
