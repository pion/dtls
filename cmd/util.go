package cmd

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"
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
		_, err = conn.Write([]byte(text))
		Check(err)
	}
}

// GenerateCertificate is a helper to generate a certificate and private key
func GenerateCertificate() (*x509.Certificate, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Check(err)

	origin := make([]byte, 16)
	Check(err)

	// Max random value, a 130-bits integer, i.e 2^130 - 1
	maxBigInt := new(big.Int)
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	serialNumber, err := rand.Int(rand.Reader, maxBigInt)
	Check(err)

	template := x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             time.Now(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotAfter:              time.Now().AddDate(0, 1, 0),
		SerialNumber:          serialNumber,
		Version:               2,
		Subject:               pkix.Name{CommonName: hex.EncodeToString(origin)},
		IsCA:                  true,
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	Check(err)

	cert, err := x509.ParseCertificate(raw)
	Check(err)

	return cert, priv
}

// Check is a helper to throw errors in the examples
func Check(err error) {
	if err != nil {
		panic(err)
	}
}
