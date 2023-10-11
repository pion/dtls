// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package dtls

import (
	"os"
	"testing"
)

func FuzzUnmarshalBinary(f *testing.F) {
	TestResumeClient, err := os.ReadFile("testdata/seed/TestResumeClient.raw")
	if err != nil {
		return
	}
	f.Add(TestResumeClient)

	TestResumeServer, err := os.ReadFile("testdata/seed/TestResumeServer.raw")
	if err != nil {
		return
	}
	f.Add(TestResumeServer)

	f.Fuzz(func(_ *testing.T, data []byte) {
		deserialized := &State{}
		_ = deserialized.UnmarshalBinary(data)
	})
}
