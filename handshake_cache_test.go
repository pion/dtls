package dtls

import (
	"bytes"
	"testing"
)

func TestHandshakeCacheSinglePush(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Rule     []handshakeCachePullRule
		Input    []handshakeCacheItem
		Expected []byte
	}{
		{
			Name: "Single Push",
			Input: []handshakeCacheItem{
				{0, true, 0, []byte{0x00}},
			},
			Rule: []handshakeCachePullRule{
				{0, true},
			},
			Expected: []byte{0x00},
		},
		{
			Name: "Multi Push",
			Input: []handshakeCacheItem{
				{0, true, 0, []byte{0x00}},
				{1, true, 1, []byte{0x01}},
				{2, true, 2, []byte{0x02}},
			},
			Rule: []handshakeCachePullRule{
				{0, true},
				{1, true},
				{2, true},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Rules set order",
			Input: []handshakeCacheItem{
				{2, true, 2, []byte{0x02}},
				{0, true, 0, []byte{0x00}},
				{1, true, 1, []byte{0x01}},
			},
			Rule: []handshakeCachePullRule{
				{0, true},
				{1, true},
				{2, true},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},

		{
			Name: "Multi Push, Dupe Seqnum",
			Input: []handshakeCacheItem{
				{0, true, 0, []byte{0x00}},
				{1, true, 1, []byte{0x01}},
				{1, true, 1, []byte{0x01}},
			},
			Rule: []handshakeCachePullRule{
				{0, true},
				{1, true},
			},
			Expected: []byte{0x00, 0x01},
		},
		{
			Name: "Multi Push, Dupe Seqnum Client/Server",
			Input: []handshakeCacheItem{
				{0, true, 0, []byte{0x00}},
				{1, true, 1, []byte{0x01}},
				{1, false, 1, []byte{0x02}},
			},
			Rule: []handshakeCachePullRule{
				{0, true},
				{1, true},
				{1, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Dupe Seqnum with Unique HandshakeType",
			Input: []handshakeCacheItem{
				{1, true, 0, []byte{0x00}},
				{2, true, 1, []byte{0x01}},
				{3, false, 0, []byte{0x02}},
			},
			Rule: []handshakeCachePullRule{
				{1, true},
				{2, true},
				{3, false},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
	} {
		h := newHandshakeCache()
		for _, i := range test.Input {
			h.push(i.data, i.messageSequence, i.typ, i.isClient)
		}
		verifyData := h.pullAndMerge(test.Rule...)
		if !bytes.Equal(verifyData, test.Expected) {
			t.Errorf("handshakeCache '%s' exp: % 02x actual % 02x", test.Name, test.Expected, verifyData)
		}
	}
}

func TestHandshakeCacheSessionHash(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Rule     []handshakeCachePullRule
		Input    []handshakeCacheItem
		Expected []byte
	}{
		{
			Name: "Standard Handshake",
			Input: []handshakeCacheItem{
				{handshakeTypeClientHello, true, 0, []byte{0x00}},
				{handshakeTypeServerHello, false, 1, []byte{0x01}},
				{handshakeTypeCertificate, false, 2, []byte{0x02}},
				{handshakeTypeServerKeyExchange, false, 3, []byte{0x03}},
				{handshakeTypeServerHelloDone, false, 4, []byte{0x04}},
				{handshakeTypeClientKeyExchange, true, 5, []byte{0x05}},
			},
			Expected: []byte{0x17, 0xe8, 0x8d, 0xb1, 0x87, 0xaf, 0xd6, 0x2c, 0x16, 0xe5, 0xde, 0xbf, 0x3e, 0x65, 0x27, 0xcd, 0x00, 0x6b, 0xc0, 0x12, 0xbc, 0x90, 0xb5, 0x1a, 0x81, 0x0c, 0xd8, 0x0c, 0x2d, 0x51, 0x1f, 0x43},
		},
		{
			Name: "Handshake With Client Cert Request",
			Input: []handshakeCacheItem{
				{handshakeTypeClientHello, true, 0, []byte{0x00}},
				{handshakeTypeServerHello, false, 1, []byte{0x01}},
				{handshakeTypeCertificate, false, 2, []byte{0x02}},
				{handshakeTypeServerKeyExchange, false, 3, []byte{0x03}},
				{handshakeTypeCertificateRequest, false, 4, []byte{0x04}},
				{handshakeTypeServerHelloDone, false, 5, []byte{0x05}},
				{handshakeTypeClientKeyExchange, true, 6, []byte{0x06}},
			},
			Expected: []byte{0x57, 0x35, 0x5a, 0xc3, 0x30, 0x3c, 0x14, 0x8f, 0x11, 0xae, 0xf7, 0xcb, 0x17, 0x94, 0x56, 0xb9, 0x23, 0x2c, 0xde, 0x33, 0xa8, 0x18, 0xdf, 0xda, 0x2c, 0x2f, 0xcb, 0x93, 0x25, 0x74, 0x9a, 0x6b},
		},
		{
			Name: "Handshake Ignores after ClientKeyExchange",
			Input: []handshakeCacheItem{
				{handshakeTypeClientHello, true, 0, []byte{0x00}},
				{handshakeTypeServerHello, false, 1, []byte{0x01}},
				{handshakeTypeCertificate, false, 2, []byte{0x02}},
				{handshakeTypeServerKeyExchange, false, 3, []byte{0x03}},
				{handshakeTypeCertificateRequest, false, 4, []byte{0x04}},
				{handshakeTypeServerHelloDone, false, 5, []byte{0x05}},
				{handshakeTypeClientKeyExchange, true, 6, []byte{0x06}},
				{handshakeTypeCertificateVerify, true, 7, []byte{0x07}},
				{handshakeTypeFinished, true, 7, []byte{0x08}},
				{handshakeTypeFinished, false, 7, []byte{0x09}},
			},
			Expected: []byte{0x57, 0x35, 0x5a, 0xc3, 0x30, 0x3c, 0x14, 0x8f, 0x11, 0xae, 0xf7, 0xcb, 0x17, 0x94, 0x56, 0xb9, 0x23, 0x2c, 0xde, 0x33, 0xa8, 0x18, 0xdf, 0xda, 0x2c, 0x2f, 0xcb, 0x93, 0x25, 0x74, 0x9a, 0x6b},
		},
	} {
		h := newHandshakeCache()
		for _, i := range test.Input {
			h.push(i.data, i.messageSequence, i.typ, i.isClient)
		}

		cipherSuite := cipherSuiteTLSEcdheEcdsaWithAes128GcmSha256{}
		verifyData, err := h.sessionHash(cipherSuite.hashFunc())
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(verifyData, test.Expected) {
			t.Errorf("handshakeCacheSesssionHassh '%s' exp: % 02x actual % 02x", test.Name, test.Expected, verifyData)
		}
	}
}
