package dtls

func findMatchingSRTPProfile(a, b []SRTPProtectionProfile) (SRTPProtectionProfile, bool) {
	for _, aProfile := range a {
		for _, bProfile := range b {
			if aProfile == bProfile {
				return aProfile, true
			}
		}
	}
	return 0, false
}

// Prefers TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA like Chrome does, also because
// pion/webrtc uses it by default without any configuration interface
// https://github.com/pion/webrtc/blob/master/dtlstransport.go#L75
func findMatchingCipherSuite(a, b []CipherSuite) (CipherSuite, bool) { //nolint
	var retSuite CipherSuite
	for _, aSuite := range a {
		for _, bSuite := range b {
			if aSuite.ID() == bSuite.ID() {
				if aSuite.ID() == TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA {
					return aSuite, true
				} else {
					retSuite = aSuite
				}
			}
		}
	}
	if retSuite != nil {
		return retSuite, true
	}
	return nil, false
}

func splitBytes(bytes []byte, splitLen int) [][]byte {
	splitBytes := make([][]byte, 0)
	numBytes := len(bytes)
	for i := 0; i < numBytes; i += splitLen {
		j := i + splitLen
		if j > numBytes {
			j = numBytes
		}

		splitBytes = append(splitBytes, bytes[i:j])
	}

	return splitBytes
}
