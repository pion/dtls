// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These vectors apply the RFC 8446 key schedule and Finished construction with
// RFC 9147 section 5.9's "dtls13" label prefix. The encoding was
// also checked with OpenSSL.
func TestKeySchedule13RegressionVectors(t *testing.T) {
	tests := []struct {
		name string
		hash func() hash.Hash

		keyAgreementSecret      string
		handshakeTranscriptHash string
		serverFinishedHash      string
		applicationHash         string
		clientFinishedHash      string
		resumptionHash          string

		clientHandshakeSecret string
		serverHandshakeSecret string
		masterSecret          string
		clientApplication     string
		serverApplication     string
		exporterMasterSecret  string
		resumptionMaster      string
		serverFinished        string
		clientFinished        string
	}{
		{
			name: "sha256",
			hash: sha256.New,
			keyAgreementSecret: "000102030405060708090a0b0c0d0e0f" +
				"101112131415161718191a1b1c1d1e1f",
			handshakeTranscriptHash: "202122232425262728292a2b2c2d2e2f" +
				"303132333435363738393a3b3c3d3e3f",
			serverFinishedHash: "404142434445464748494a4b4c4d4e4f" +
				"505152535455565758595a5b5c5d5e5f",
			applicationHash: "606162636465666768696a6b6c6d6e6f" +
				"707172737475767778797a7b7c7d7e7f",
			clientFinishedHash: "808182838485868788898a8b8c8d8e8f" +
				"909192939495969798999a9b9c9d9e9f",
			resumptionHash: "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
				"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
			clientHandshakeSecret: "48834a5e86b1a984eaf5a77b8552e0b5" +
				"1a0878fbfc8e8e4098331f2666e6c283",
			serverHandshakeSecret: "74b4bd30abf8fb590f64801397eb7c4a" +
				"4f1a7043b8a51b01b619d6288af8d639",
			masterSecret: "219a76ca5664f6da265aaa2f1336525f" +
				"b3db2c8b9a6da9e29b5fa7e4107d17e4",
			clientApplication: "bce5f20cbbe8e905fb14f770a4476c12" +
				"5f205e12f823535eccf19479da7600ef",
			serverApplication: "4514b3035c3be36a4e51b693c3ffb44f" +
				"4b07027afd2fa3d736675d6094c2a4e7",
			exporterMasterSecret: "432323faec5c4bb685a39a140564e901" +
				"ec42f7bf3d2de56a874806661567dbb3",
			resumptionMaster: "fcd8551edc0e575f85a61b92fb913765" +
				"82b703d2d51c3e0f61e5f9cb2c779c68",
			serverFinished: "08ede3f490fa46ce7f920594d96c5d65" +
				"4a3b5d1bc58b84502394a7c55d8eeda5",
			clientFinished: "8cdf48eafa26f1712fcdd4fd0ab2144b" +
				"3df17d2a26ed6ba83fff410770f19607",
		},
		{
			name: "sha384",
			hash: sha512.New384,
			keyAgreementSecret: "000102030405060708090a0b0c0d0e0f" +
				"101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f",
			handshakeTranscriptHash: "202122232425262728292a2b2c2d2e2f" +
				"303132333435363738393a3b3c3d3e3f" +
				"404142434445464748494a4b4c4d4e4f",
			serverFinishedHash: "404142434445464748494a4b4c4d4e4f" +
				"505152535455565758595a5b5c5d5e5f" +
				"606162636465666768696a6b6c6d6e6f",
			applicationHash: "606162636465666768696a6b6c6d6e6f" +
				"707172737475767778797a7b7c7d7e7f" +
				"808182838485868788898a8b8c8d8e8f",
			clientFinishedHash: "808182838485868788898a8b8c8d8e8f" +
				"909192939495969798999a9b9c9d9e9f" +
				"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			resumptionHash: "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
				"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
				"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
			clientHandshakeSecret: "cc8f6bcd3db0cd04477c6084b3d3523c" +
				"da1cf2b28dfd354efbb26c002e66c651" +
				"d1730165a51ee1448f9b07f11713424e",
			serverHandshakeSecret: "87aa67663f33bc3300d19c8bef046946" +
				"3ad0b3b3150b97fa4df1adcef9fc785a" +
				"2a47a17f0dce9430029e16f7f0631094",
			masterSecret: "fa7b25f9a83b5117689a08098f4ab690" +
				"beeb5b2dfdac96ab9c8ea965e76ac2d7" +
				"5147b21ea1a1c71590f966d572da10c8",
			clientApplication: "6a2eb3acb47a5f9fa682079b120507d1" +
				"7ec650fef3c7c00a06b1fdea3b4a7e98" +
				"8752ab30a2378d6abf5fd965a0a8d74f",
			serverApplication: "f6eb012422f600a6d4a0a3a78a5baa8d" +
				"ebd71f30a20af15783046ff4cef28c47" +
				"69ae893afe65d718f8cff5eaad93b3f8",
			exporterMasterSecret: "69e9f076aaab9e68a16be160cfaa2235" +
				"6276bd51db9dc6db41f392e22874d6d0" +
				"0ead96a2d55939364f81517eed6909cb",
			resumptionMaster: "e49078972d79a1b8065f6f1eef58cce3" +
				"f07df2628b61e72770ea1bb19aae5004" +
				"9180e8fd06498cfe4e32d74ca184026b",
			serverFinished: "ebd4969113fd1c77ede80b0072d9f79f" +
				"31a8edea666a91596fedf00496d007f2" +
				"cbac3aa1a1914d6ec900a7f0d5c41f57",
			clientFinished: "feeaba4a756bed6b8534df7d47a9f425" +
				"1fe121785008de45de4535bf47b70b61" +
				"b6fff9d3400566f4a25df11b2eca3819",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyAgreementSecret := decodeRegressionHex(t, test.keyAgreementSecret)
			handshakeHash := decodeRegressionHex(t, test.handshakeTranscriptHash)

			schedule, err := deriveHandshakeKeySchedule(test.hash, keyAgreementSecret, handshakeHash)
			require.NoError(t, err)
			assert.Equal(t, decodeRegressionHex(t, test.clientHandshakeSecret),
				schedule.HandshakeTrafficSecrets.Client)
			assert.Equal(t, decodeRegressionHex(t, test.serverHandshakeSecret),
				schedule.HandshakeTrafficSecrets.Server)
			assert.Equal(t, decodeRegressionHex(t, test.masterSecret), schedule.MasterSecret)

			applicationHash := decodeRegressionHex(t, test.applicationHash)
			application, err := deriveApplicationTrafficSecrets(test.hash, schedule.MasterSecret, applicationHash)
			require.NoError(t, err)
			assert.Equal(t, decodeRegressionHex(t, test.clientApplication), application.Client)
			assert.Equal(t, decodeRegressionHex(t, test.serverApplication), application.Server)

			exporter, err := deriveExporterMasterSecret(test.hash, schedule.MasterSecret, applicationHash)
			require.NoError(t, err)
			assert.Equal(t, decodeRegressionHex(t, test.exporterMasterSecret), exporter)

			resumption, err := deriveResumptionMasterSecret(
				test.hash,
				schedule.MasterSecret,
				decodeRegressionHex(t, test.resumptionHash),
			)
			require.NoError(t, err)
			assert.Equal(t, decodeRegressionHex(t, test.resumptionMaster), resumption)

			serverFinished, err := finishedVerifyData(
				test.hash,
				schedule.HandshakeTrafficSecrets.Server,
				decodeRegressionHex(t, test.serverFinishedHash),
			)
			require.NoError(t, err)
			expectedServerFinished := decodeRegressionHex(t, test.serverFinished)
			assert.Equal(t, expectedServerFinished, serverFinished)
			assert.NoError(t, verifyFinishedData(
				test.hash,
				schedule.HandshakeTrafficSecrets.Server,
				decodeRegressionHex(t, test.serverFinishedHash),
				expectedServerFinished,
			))

			clientFinished, err := finishedVerifyData(
				test.hash,
				schedule.HandshakeTrafficSecrets.Client,
				decodeRegressionHex(t, test.clientFinishedHash),
			)
			require.NoError(t, err)
			expectedClientFinished := decodeRegressionHex(t, test.clientFinished)
			assert.Equal(t, expectedClientFinished, clientFinished)
			assert.NoError(t, verifyFinishedData(
				test.hash,
				schedule.HandshakeTrafficSecrets.Client,
				decodeRegressionHex(t, test.clientFinishedHash),
				expectedClientFinished,
			))
		})
	}
}

func decodeRegressionHex(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	require.NoError(t, err)

	return decoded
}
