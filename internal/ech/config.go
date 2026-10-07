// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ech implements wire and cryptographic helpers for https://www.rfc-editor.org/rfc/rfc9849.
package ech

import (
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/pion/dtls/v4/internal/clienthello"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	"golang.org/x/crypto/cryptobyte"
)

const Version uint16 = 0xfe0d

var (
	ErrInvalid     = errors.New("malformed ECH encoding")
	ErrUnsupported = errors.New("unsupported ECH configuration")
	ErrToolchain   = errors.New("ECH requires Go 1.26 or later")
)

// CipherSuite identifies an HPKE symmetric cipher suite.
type CipherSuite struct{ KDFID, AEADID uint16 }

// Config retains the original encoding, which is authenticated by HPKE.
type Config struct {
	Raw                  []byte
	Version              uint16
	Length               uint16
	ConfigID             uint8
	KemID                uint16
	PublicKey            []byte
	SymmetricCipherSuite []CipherSuite
	MaxNameLength        uint8
	PublicName           string
	Extensions           []extension.Raw
}

// ParseConfig parses exactly one ECHConfig, skipping unknown versions.
// Like crypto/tls, it leaves key, suite, and name usability to selection.
func ParseConfig(data []byte) (skip bool, config Config, err error) {
	input := cryptobyte.String(data)
	if !input.ReadUint16(&config.Version) || !input.ReadUint16(&config.Length) || len(input) != int(config.Length) {
		return false, Config{}, ErrInvalid
	}
	if config.Version != Version {
		return true, Config{}, nil
	}
	config.Raw = bytes.Clone(data)
	if err := config.parseContents(input); err != nil {
		return false, Config{}, err
	}

	return false, config, nil
}

// ParseConfigList validates framing and skips unknown configuration versions,
// preserving the server's preference order.
func ParseConfigList(data []byte) ([]Config, error) {
	input := cryptobyte.String(data)
	var list cryptobyte.String
	if !input.ReadUint16LengthPrefixed(&list) || !input.Empty() || len(list) < 4 {
		return nil, ErrInvalid
	}
	var configs []Config
	for !list.Empty() {
		original := list
		var body cryptobyte.String
		if !list.Skip(2) || !list.ReadUint16LengthPrefixed(&body) {
			return nil, ErrInvalid
		}
		skip, config, err := ParseConfig(original[:len(original)-len(list)])
		if err != nil {
			return nil, err
		}
		if !skip {
			configs = append(configs, config)
		}
	}

	return configs, nil
}

func (config *Config) parseContents(input cryptobyte.String) error { //nolint:cyclop // Parse fields in wire order.
	var publicKey, suites, name cryptobyte.String
	if !input.ReadUint8(&config.ConfigID) || !input.ReadUint16(&config.KemID) ||
		!input.ReadUint16LengthPrefixed(&publicKey) || !input.ReadUint16LengthPrefixed(&suites) {
		return ErrInvalid
	}
	config.PublicKey = bytes.Clone(publicKey)
	for !suites.Empty() {
		var suite CipherSuite
		if !suites.ReadUint16(&suite.KDFID) || !suites.ReadUint16(&suite.AEADID) {
			return ErrInvalid
		}
		config.SymmetricCipherSuite = append(config.SymmetricCipherSuite, suite)
	}
	if !input.ReadUint8(&config.MaxNameLength) || !input.ReadUint8LengthPrefixed(&name) {
		return ErrInvalid
	}
	config.PublicName = string(name)
	extensions, err := extension.ParseList(input)
	if err != nil || clienthello.ValidateExtensions(extensions, false) != nil {
		return ErrInvalid
	}
	config.Extensions = extensions

	return nil
}

// Usable checks public-name syntax and rejects
// unsupported mandatory configuration extensions.
func (config Config) Usable() bool {
	// Reject public names the certificate verifier would interpret as IP addresses.
	// RFC 9849, Section 6.1.7 explicitly rejects IPv4. IPv6 literals, including
	// scoped addresses, are already excluded by the DNS syntax (they contain ':').
	// Inintally we adopted golang's behavior because we thought it was intended to
	// allow IPv4, but we sent them a patch and it turned out to be a mistake on their side.
	// https://go-review.googlesource.com/c/go/+/845746
	if _, err := netip.ParseAddr(config.PublicName); err == nil {
		return false
	}
	if len(config.PublicName) > 253 || !strings.Contains(config.PublicName, ".") {
		return false
	}
	for label := range strings.SplitSeq(config.PublicName, ".") {
		invalidCharacter := strings.ContainsFunc(label, invalidDNSCharacter)
		if len(label) == 0 || label[0] == '-' || label[len(label)-1] == '-' || invalidCharacter {
			return false
		}
	}

	return !slices.ContainsFunc(config.Extensions, func(e extension.Raw) bool { return uint16(e.Type)&0x8000 != 0 })
}

func invalidDNSCharacter(ch rune) bool {
	return ch != '-' && (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9')
}

// Sender and Recipient retain HPKE sequence state across ClientHellos.
type Sender interface {
	Seal(aad, plaintext []byte) ([]byte, error)
	Export(string, int) ([]byte, error)
}
type Recipient interface {
	Open(aad, ciphertext []byte) ([]byte, error)
	Export(string, int) ([]byte, error)
}
