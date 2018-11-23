package dtls

type handshakeCacheItem struct {
	flight                 flightVal
	isLocal                bool
	epoch, messageSequence uint16
	data                   []byte
}

type handshakeCache struct {
	cache []handshakeCacheItem
}

func newHandshakeCache(isClient bool) *handshakeCache {
	return &handshakeCache{}
}

func (h *handshakeCache) push(data []byte, epoch, messageSequence uint16, isLocal bool, currentFlight flightVal) {
	for _, i := range h.cache {
		if i.isLocal == isLocal &&
			i.epoch == epoch &&
			i.messageSequence == messageSequence {
			return
		}
	}
	h.cache = append(h.cache, handshakeCacheItem{
		flight:          currentFlight,
		data:            append([]byte{}, data...),
		epoch:           epoch,
		messageSequence: messageSequence,
		isLocal:         isLocal,
	})
}

type handshakeCacheExcludeRule struct {
	isLocal  bool // Exclude handshake if we sent
	isRemote bool // Exclude handshake if remote sent
}

func (h *handshakeCache) combinedHandshake(excludeRules map[flightVal]handshakeCacheExcludeRule) []byte {
	out := make([]byte, 0)
	for _, v := range h.cache {
		if e, ok := excludeRules[v.flight]; ok {
			if e.isLocal && v.isLocal {
				continue
			} else if e.isRemote && !v.isLocal {
				continue
			}
		}
		out = append(out, v.data...)
	}
	return out
}
