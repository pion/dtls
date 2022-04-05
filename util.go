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

func findMatchingCipherSuite(remote, local []CipherSuite) (CipherSuite, bool) { //nolint
	for _, aSuite := range local {
		for _, bSuite := range remote {
			if aSuite.ID() == bSuite.ID() {
				return aSuite, true
			}
		}
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
