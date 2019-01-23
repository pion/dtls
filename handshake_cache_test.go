package dtls

import (
	"bytes"
	"testing"
)

func TestHandshakeCacheSinglePush(t *testing.T) {
	for _, test := range []struct {
		Name     string
		Input    []handshakeCacheItem
		Expected []byte
	}{
		{
			Name: "Single Push",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
			},
			Expected: []byte{0x00},
		},
		{
			Name: "Multi Push",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
				{0, true, 0, 1, []byte{0x01}},
				{0, true, 0, 2, []byte{0x02}},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Dupe Seqnum",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
				{0, true, 0, 1, []byte{0x01}},
				{0, true, 0, 1, []byte{0x01}},
			},
			Expected: []byte{0x00, 0x01},
		},
		{
			Name: "Multi Push, Dupe Seqnum Client/Server",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
				{0, true, 0, 1, []byte{0x01}},
				{0, false, 0, 1, []byte{0x02}},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
		{
			Name: "Multi Push, Dupe Seqnum with Unique Epoch",
			Input: []handshakeCacheItem{
				{0, true, 0, 0, []byte{0x00}},
				{0, true, 0, 1, []byte{0x01}},
				{0, false, 1, 1, []byte{0x02}},
			},
			Expected: []byte{0x00, 0x01, 0x02},
		},
	} {
		h := newHandshakeCache()
		for _, i := range test.Input {
			h.push(i.data, i.epoch, i.messageSequence, i.isLocal, flight6)
		}
		verifyData := h.combinedHandshake(map[flightVal]handshakeCacheExcludeRule{}, false)
		if !bytes.Equal(verifyData, test.Expected) {
			t.Errorf("handshakeCache '%s' exp: % 02x actual % 02x", test.Name, test.Expected, verifyData)
		}
	}
}
