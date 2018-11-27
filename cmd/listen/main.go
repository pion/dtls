package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/pions/dtls/cmd"
	"github.com/pions/dtls/pkg/dtls"
)

func main() {
	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4444}

	// Generate a certificate and private key to secure the connection
	certificate, privateKey := cmd.GenerateCertificate()

	//
	// Everything below is the pion-DTLS API! Thanks for using it ❤️.
	//

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{certificate, privateKey}

	// Connect to a DTLS server
	listener, err := dtls.Listen("udp", addr, config)
	cmd.Check(err)
	defer listener.Close()

	// Simulate a chat session
	hub := NewHub()
	go hub.chat()

	for {
		// Wait for a connection.
		conn, err := listener.Accept()
		cmd.Check(err)

		// Register the connection with the chat hub
		hub.register(conn)
	}
}

const bufSize = 8192

// hub is a helper to handle one to many chat
type hub struct {
	conns map[string]net.Conn
	lock  sync.RWMutex
}

func NewHub() *hub {
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
	fmt.Println("Disconnecting ", conn.RemoteAddr())
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.conns, conn.RemoteAddr().String())
	_ = conn.Close()
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
		cmd.Check(err)
		h.broadcast([]byte(msg))
	}
}
