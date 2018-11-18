package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/pions/dtls/internal/ice"
	"github.com/pions/dtls/pkg/dtls"
)

const bufSize = 8192

func main() {
	a, _ := ice.Listen("127.0.0.1:4444", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555})

	certificate, privateKey := generateCertificate()
	dtlsConn, err := dtls.Server(a, certificate, privateKey)
	check(err)
	defer dtlsConn.Close()

	b := make([]byte, bufSize)
	for {
		n, err := dtlsConn.Read(b)
		check(err)
		fmt.Printf("Got message: %s\n", string(b[:n]))
	}
}

func generateCertificate() (*x509.Certificate, *ecdsa.PrivateKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)

	origin := make([]byte, 16)
	check(err)

	// Max random value, a 130-bits integer, i.e 2^130 - 1
	maxBigInt := new(big.Int)
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	serialNumber, err := rand.Int(rand.Reader, maxBigInt)
	check(err)

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
	check(err)

	cert, err := x509.ParseCertificate(raw)
	check(err)

	return cert, priv
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
