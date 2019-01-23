package util

import (
	"bufio"
	"fmt"
	"io"
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
			if err != nil {
				return
			}
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
	if err != nil {
		panic(err)
	}
}
