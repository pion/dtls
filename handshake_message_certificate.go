package dtls

type handshakeMessageCertificate struct {
	certificate [][]byte
}

func (h handshakeMessageCertificate) handshakeType() handshakeType {
	return handshakeTypeCertificate
}

func (h *handshakeMessageCertificate) Marshal() ([]byte, error) {
	certTotalLen := 0
	for _, r := range h.certificate {
		certTotalLen += len(r)
	}
	outLen := len(h.certificate)*3 + certTotalLen
	if outLen < 6 {
		out := make([]byte, 6)
		putBigEndianUint24(out, 3)
		return out, nil
	}
	out := make([]byte, outLen+3)
	putBigEndianUint24(out, uint32(outLen))
	iter := out[3:]
	for _, r := range h.certificate {
		putBigEndianUint24(iter, uint32(len(r)))
		iter = iter[3:]
		copy(iter, r)
		iter = iter[len(r):]
	}
	return out, nil
}

func (h *handshakeMessageCertificate) Unmarshal(data []byte) error {
	if len(data) < 6 {
		return errBufferTooSmall
	}

	certificateBodyLen := int(bigEndianUint24(data))
	if certificateBodyLen+3 != len(data) {
		return errLengthMismatch
	}
	iter := data[3:]

	for len(iter) != 0 {
		certificateLen := int(bigEndianUint24(iter))
		iter = iter[3:]
		if certificateLen > len(iter) {
			return errLengthMismatch
		}
		if certificateLen == 0 {
			if len(iter) > 0 {
				return errLengthMismatch
			}
			return nil
		}
		h.certificate = append(h.certificate, iter[:certificateLen])
		iter = iter[certificateLen:]
	}

	return nil
}
