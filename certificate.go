package dtls

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
)

func (c *handshakeConfig) getCertificate(serverName string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	certs := c.localCertificates
	if len(c.localCertificates) == 0 && c.getCertificateFunc != nil {
		cert, err := c.getCertificateFunc(&tls.ClientHelloInfo{
			ServerName: serverName,
		})
		if err != nil {
			return nil, err
		}
		if cert != nil {
			// TODO(zllovesuki): can we do away with allocation in hot path?
			certs = []tls.Certificate{*cert}
		}
	}

	if c.nameToCertificate == nil {
		nameToCertificate := make(map[string]*tls.Certificate)
		for i := range certs {
			cert := &certs[i]
			x509Cert := cert.Leaf
			if x509Cert == nil {
				var parseErr error
				x509Cert, parseErr = x509.ParseCertificate(cert.Certificate[0])
				if parseErr != nil {
					continue
				}
			}
			if len(x509Cert.Subject.CommonName) > 0 {
				nameToCertificate[strings.ToLower(x509Cert.Subject.CommonName)] = cert
			}
			for _, san := range x509Cert.DNSNames {
				nameToCertificate[strings.ToLower(san)] = cert
			}
		}
		c.nameToCertificate = nameToCertificate
	}

	if len(certs) == 0 {
		return nil, errNoCertificates
	}

	if len(certs) == 1 {
		// There's only one choice, so no point doing any work.
		return &certs[0], nil
	}

	if len(serverName) == 0 {
		return &certs[0], nil
	}

	name := strings.TrimRight(strings.ToLower(serverName), ".")

	if cert, ok := c.nameToCertificate[name]; ok {
		return cert, nil
	}

	// try replacing labels in the name with wildcards until we get a
	// match.
	labels := strings.Split(name, ".")
	for i := range labels {
		labels[i] = "*"
		candidate := strings.Join(labels, ".")
		if cert, ok := c.nameToCertificate[candidate]; ok {
			return cert, nil
		}
	}

	// If nothing matches, return the first certificate.
	return &certs[0], nil
}
