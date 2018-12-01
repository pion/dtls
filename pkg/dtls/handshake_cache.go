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

func newHandshakeCache() *handshakeCache {
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

func (h *handshakeCache) combinedHandshake(excludeRules map[flightVal]handshakeCacheExcludeRule, excludeLast bool) []byte {
	out := make([]byte, 0)
	lastIndex := len(h.cache) - 1 // Safe if len(h.cache) == 0, no loop will occur
	for i, v := range h.cache {
		if e, ok := excludeRules[v.flight]; ok {
			if e.isLocal && v.isLocal {
				continue
			} else if e.isRemote && !v.isLocal {
				continue
			}
		} else if excludeLast && i == lastIndex {
			break
		}
		out = append(out, v.data...)
	}
	return out
}
