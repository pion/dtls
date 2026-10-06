// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package ech

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

func configList(publicKey []byte) []byte {
	return configListFor(Config{
		ConfigID: 7, KemID: 32, PublicKey: publicKey,
		SymmetricCipherSuite: []CipherSuite{{1, 1}},
		MaxNameLength:        32, PublicName: "public.example",
	})
}

func configListFor(configs ...Config) []byte {
	var builder cryptobyte.Builder
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		for _, config := range configs {
			builder.AddUint16(Version)
			builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
				builder.AddUint8(config.ConfigID)
				builder.AddUint16(config.KemID)
				builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) { builder.AddBytes(config.PublicKey) })
				builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
					for _, suite := range config.SymmetricCipherSuite {
						builder.AddUint16(suite.KDFID)
						builder.AddUint16(suite.AEADID)
					}
				})
				builder.AddUint8(config.MaxNameLength)
				builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) { builder.AddBytes([]byte(config.PublicName)) })
				extensions, err := extension.MarshalRawList(config.Extensions)
				builder.SetError(err)
				builder.AddBytes(extensions)
			})
		}
	})

	return builder.BytesOrPanic()
}

func TestConfigSelection(t *testing.T) {
	configs, err := ParseConfigList(configList(bytes.Repeat([]byte{1}, 32)))
	require.NoError(t, err)
	good := configs[0]
	good.SymmetricCipherSuite = []CipherSuite{{0xffff, 1}, {1, 0xffff}, {1, 1}}
	for name, change := range map[string]func(*Config){
		"empty_key":           func(config *Config) { config.PublicKey = nil },
		"empty_suites":        func(config *Config) { config.SymmetricCipherSuite = nil },
		"empty_name":          func(config *Config) { config.PublicName = "" },
		"bad_key":             func(config *Config) { config.PublicKey = []byte{1} },
		"mandatory_extension": func(config *Config) { config.Extensions = []extension.Raw{{Type: 0x8000}} },
		"unsupported_kem":     func(config *Config) { config.KemID = 0xffff },
		"bad_name":            func(config *Config) { config.PublicName = "localhost" },
		"unsupported_suites":  func(config *Config) { config.SymmetricCipherSuite = []CipherSuite{{0xffff, 1}, {1, 0xffff}} },
	} {
		t.Run(name, func(t *testing.T) {
			config := good
			change(&config)
			parsed, err := ParseConfigList(configListFor(config, good))
			require.NoError(t, err)
			require.Len(t, parsed, 2)
			require.Equal(t, configListFor(good)[2:], parsed[1].Raw)
			if Available() {
				selected, suite, err := PickConfig(parsed)
				require.NoError(t, err)
				require.Same(t, &parsed[1], selected)
				require.Equal(t, CipherSuite{1, 1}, suite)
				_, _, err = PickConfig(parsed[:1])
				require.ErrorIs(t, err, ErrUnsupported)
			}
		})
	}
}

func hello(t *testing.T, session []byte, exts ...extension.Value) []byte {
	t.Helper()
	require.LessOrEqual(t, len(session), 32)
	message := handshake.MessageClientHello{
		Version: protocol.Version1_2, Random: handshake.Random{GMTUnixTime: time.Unix(0, 0)},
		SessionID: session, CipherSuiteIDs: []uint16{0x1301},
		CompressionMethods: []*protocol.CompressionMethod{{ID: 0}}, Extensions: exts,
	}
	encoded, err := message.Marshal()
	require.NoError(t, err)

	return encoded
}

func TestConfigList(t *testing.T) {
	data := configList(bytes.Repeat([]byte{1}, 32))
	configs, err := ParseConfigList(data)
	require.NoError(t, err)
	require.Len(t, configs, 1)
	require.True(t, configs[0].Usable())
	require.Equal(t, data[2:], configs[0].Raw)
	skip, config, err := ParseConfig(data[2:])
	require.NoError(t, err)
	require.False(t, skip)
	require.Equal(t, configs[0], config)
	require.Equal(t, Version, config.Version)
	require.Equal(t, len(data)-6, int(config.Length))
	require.Equal(t, uint8(7), config.ConfigID)
	require.Equal(t, uint16(32), config.KemID)
	for i := range data {
		_, err = ParseConfigList(data[:i])
		require.Error(t, err, "prefix %d", i)
	}
	_, err = ParseConfigList(append(bytes.Clone(data), 0))
	require.Error(t, err)
	_, _, err = ParseConfig(append(bytes.Clone(data[2:]), 0))
	require.ErrorIs(t, err, ErrInvalid)
	_, _, err = ParseConfig([]byte{0xfe, 0x0d, 0, 0})
	require.ErrorIs(t, err, ErrInvalid)
	unknown := bytes.Clone(data)
	unknown[2] = 0
	unknown[3] = 1
	configs, err = ParseConfigList(unknown)
	require.NoError(t, err)
	require.Empty(t, configs)
	data[6] ^= 0xff
	require.Equal(t, uint8(7), config.Raw[4])
	c := Config{PublicName: "public.example", Extensions: []extension.Raw{{Type: 0x8000}}}
	require.False(t, c.Usable())
	for _, name := range []string{
		"public.example", "Public-Name.EXAMPLE", "127.0.0.1", "127.1", "public.123", "public.0x",
		strings.Repeat("a", 64) + ".example", strings.Repeat("a", 245) + ".example",
	} {
		require.True(t, (Config{PublicName: name}).Usable(), "name %q", name)
	}
	for _, name := range []string{
		"", "localhost", "2130706433", "0x7f000001", "-bad.example", "bad-.example",
		"bad..example", ".bad.example", "bad.example.", "bad_name.example", "bäd.example", "::1",
		strings.Repeat("a", 246) + ".example",
	} {
		require.False(t, (Config{PublicName: name}).Usable(), "name %q", name)
	}
}

func TestInnerAndAAD(t *testing.T) {
	shared := extension.Raw{Type: extension.TypeSupportedGroups, Data: []byte{0, 2, 0, 29}}
	tail := extension.Raw{Type: 0x1234, Data: []byte{8}}
	versions := extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}}
	outerECH := extension13.ECHClientHello{KDF: 1, AEAD: 1, ConfigID: 7, Enc: []byte{1, 2}, Payload: bytes.Repeat([]byte{9}, 40)}
	outer := hello(t, []byte{3, 4}, versions, shared, outerECH)
	inner := hello(t, []byte{3, 4}, extension13.ECHClientHello{Type: extension13.ECHClientHelloInner}, versions, shared, tail)
	compressed := hello(t, []byte{3, 4}, extension13.ECHClientHello{Type: extension13.ECHClientHelloInner},
		extension13.ECHOuterExtensions{Types: []extension.Type{extension.TypeSupportedVersions, shared.Type}}, tail)
	encoded, err := EncodeInnerClientHello(compressed, 32, 12)
	require.NoError(t, err)
	require.Zero(t, len(encoded)%32)
	decoded, err := DecodeInnerClientHello(encoded, outer)
	require.NoError(t, err)
	require.Equal(t, inner, decoded)
	bad := bytes.Clone(encoded)
	bad[len(bad)-1] = 1
	_, err = DecodeInnerClientHello(bad, outer)
	require.Error(t, err)
	_, err = DecodeInnerClientHello(encoded, hello(t, nil, outerECH))
	require.Error(t, err)
	duplicate := hello(t, nil, extension13.ECHClientHello{Type: extension13.ECHClientHelloInner}, versions, shared, extension13.ECHOuterExtensions{Types: []extension.Type{shared.Type}})
	encoded, err = EncodeInnerClientHello(duplicate, 32, -1)
	require.NoError(t, err)
	_, err = DecodeInnerClientHello(encoded, outer)
	require.Error(t, err)
	before := bytes.Clone(outer)
	aad, err := OuterAAD(outer)
	require.NoError(t, err)
	require.Equal(t, before, outer)
	outerECH.Payload = make([]byte, 40)
	require.Equal(t, hello(t, []byte{3, 4}, versions, shared, outerECH), aad)
	for i := range outer {
		_, err = OuterAAD(outer[:i])
		require.Error(t, err)
	}
}

func FuzzECH(f *testing.F) {
	f.Add(configList(bytes.Repeat([]byte{1}, 32)), []byte{})
	f.Add([]byte{0, 4, 0, 1, 0, 0}, []byte{})
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, inner, outer []byte) {
		configs, _ := ParseConfigList(inner)
		for _, c := range configs {
			require.NotEmpty(t, c.Raw)
			_ = c.Usable()
		}
		_, _ = OuterAAD(outer)
		_, _ = EncodeInnerClientHello(inner, 32, -1)
		_, _ = DecodeInnerClientHello(inner, outer)
	})
}
