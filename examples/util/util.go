// Package util provides auxiliary utilities used in examples
package util

import (
	"bufio"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const bufSize = 8192

var (
	errBlockIsNotCertificate = errors.New("block is not a certificate, unable to load certificates")
	errNoCertificateFound    = errors.New("no certificate found, unable to load certificates")
)

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
	var netError net.Error
	if errors.As(err, &netError) && netError.Temporary() { //nolint:staticcheck
		fmt.Printf("Warning: %v\n", err)
	} else if err != nil {
		fmt.Printf("error: %v\n", err)
		panic(err)
	}
}

// LoadKeyAndCertificate reads certificates or key from file
func LoadKeyAndCertificate(keyPath string, certificatePath string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certificatePath, keyPath)
}

// LoadCertificate Load/read certificate(s) from file
func LoadCertificate(path string) (*tls.Certificate, error) {
	rawData, err := ioutil.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	var certificate tls.Certificate

	for {
		block, rest := pem.Decode(rawData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return nil, errBlockIsNotCertificate
		}

		certificate.Certificate = append(certificate.Certificate, block.Bytes)
		rawData = rest
	}

	if len(certificate.Certificate) == 0 {
		return nil, errNoCertificateFound
	}

	return &certificate, nil
}
