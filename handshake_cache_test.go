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
