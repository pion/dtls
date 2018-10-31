package dtls

type fragment struct {
	handshakeHeader handshakeHeader
	data            []byte
}

type fragmentBuffer struct {
	// map of MessageSequenceNumbers that hold slices of fragments
	cache map[uint16][]*fragment

	currentEpoch       uint16
	lastSequenceNumber uint64
}

func createFragmentBuffer() *fragmentBuffer {
	return &fragmentBuffer{cache: map[uint16][]*fragment{}}
}

func (f *fragmentBuffer) push(frag *fragment, epoch uint16) {
	// If the pushed epoch is greater then the current discard everything
	// if the pushed epoch is less then discard the packet
	//
	// implementations SHOULD discard packets from earlier epochs
	// https://tools.ietf.org/html/rfc6347#section-4.1
	if f.currentEpoch < epoch {
		f.cache = map[uint16][]*fragment{}
		f.currentEpoch = 0
	} else if f.currentEpoch > epoch {
		return
	}

	if _, ok := f.cache[frag.handshakeHeader.messageSequence]; !ok {
		f.cache[frag.handshakeHeader.messageSequence] = []*fragment{}
	}
	f.cache[frag.handshakeHeader.messageSequence] = append(f.cache[frag.handshakeHeader.messageSequence], frag)
}

func (f *fragmentBuffer) pop() []byte {
	_, ok := f.cache[f.currentEpoch+1]
	if !ok {
		return nil
	}

	return nil
}
