package ciphersuite

import (
	"github.com/pion/dtls/v2/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v2/pkg/crypto/clientcertificate"
)

// Aes256Ccm is a base class used by multiple AES-CCM Ciphers
type Aes256Ccm struct {
	AesCcm
}

func newAes256Ccm(clientCertificateType clientcertificate.Type, id ID, psk bool, cryptoCCMTagLen ciphersuite.CCMTagLen) *Aes256Ccm {
	return &Aes256Ccm{
		AesCcm: AesCcm{
			clientCertificateType: clientCertificateType,
			id:                    id,
			psk:                   psk,
			cryptoCCMTagLen:       cryptoCCMTagLen,
		},
	}
}

// Init initializes the internal Cipher with keying material
func (c *Aes256Ccm) Init(masterSecret, clientRandom, serverRandom []byte, isClient bool) error {
	const prfKeyLen = 32
	return c.AesCcm.Init(masterSecret, clientRandom, serverRandom, isClient, prfKeyLen)
}
