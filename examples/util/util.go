// Package util provides auxiliary utilities used in examples
package util

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

const bufSize = 8192

// Chat simulates a simple text chat session over the connection
func Chat(conn io.ReadWriter) {
	go func() {
		b := make([]byte, bufSize)
		for {
			n, err := conn.Read(b)
			Check(err)
			fmt.Printf("Got message: %s\n", string(b[:n]))
		}
	}()

	reader := bufio.NewReader(os.Stdin)
	for {
		text, err := reader.ReadString('\n')
		Check(err)
		if strings.TrimSpace(text) == "exit" {
			return
		}
		_, err = conn.Write([]byte(text))
		Check(err)
	}
}

// Check is a helper to throw errors in the examples
func Check(err error) {
	switch e := err.(type) {
	case nil:
	case (net.Error):
		if e.Temporary() {
			fmt.Printf("Warning: %v\n", err)
			return
		}
		fmt.Printf("net.Error: %v\n", err)
		panic(err)
	default:
		fmt.Printf("error: %v\n", err)
		panic(err)
	}
}
