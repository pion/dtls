// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import "crypto/rand"

// RandomCIDGenerator is a random Connection ID generator where CID is the
// specified size. Specifying a size of 0 will indicate to peers that sending a
// Connection ID is not necessary.
func RandomCIDGenerator(size int) func() []byte {
	return func() []byte {
		cid := make([]byte, size)
		if _, err := rand.Read(cid); err != nil {
			panic(err) //nolint -- nonrecoverable
		}
		return cid
	}
}

// OnlySendCIDGenerator enables sending Connection IDs negotiated with a peer,
// but indicates to the peer that sending Connection IDs in return is not
// necessary.
func OnlySendCIDGenerator() func() []byte {
	return func() []byte {
		return nil
	}
}
