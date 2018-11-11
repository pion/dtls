package dtls

type handshakeCacheItem struct {
	isLocal                bool
	epoch, messageSequence uint16
	data                   []byte
}

type handshakeCache struct {
	cache []handshakeCacheItem
}

func newHandshakeCache() *handshakeCache {
	return &handshakeCache{}
}

func (h *handshakeCache) push(data []byte, epoch, messageSequence uint16, isLocal bool) {
	for _, i := range h.cache {
		if i.isLocal == isLocal &&
			i.epoch == epoch &&
			i.messageSequence == messageSequence {
			return
		}
	}
	h.cache = append(h.cache, handshakeCacheItem{
		data:            append([]byte{}, data...),
		epoch:           epoch,
		messageSequence: messageSequence,
		isLocal:         isLocal,
	})
}

func (h *handshakeCache) combinedHandshake() []byte {
	out := make([]byte, 0)
	for _, v := range h.cache {
		out = append(out, v.data...)
	}
	return out
}
