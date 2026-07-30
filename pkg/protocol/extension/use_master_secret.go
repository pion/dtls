// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

// UseExtendedMasterSecret defines a TLS extension that contextually binds the
// master secret to a log of the full handshake that computes it, thus
// preventing MITM attacks.
type UseExtendedMasterSecret struct {
	Supported bool
}

// TypeValue returns the extension TypeValue.
func (u UseExtendedMasterSecret) TypeValue() TypeValue {
	return UseExtendedMasterSecretTypeValue
}

// Marshal encodes the extension.
func (u *UseExtendedMasterSecret) Marshal() ([]byte, error) {
	return marshalEmptyExtension(u.TypeValue(), u.Supported)
}

// Unmarshal populates the extension from encoded data.
func (u *UseExtendedMasterSecret) Unmarshal(data []byte) error {
	payload, err := extensionPayload(data, u.TypeValue())
	if err != nil {
		return err
	}

	return u.unmarshalPayload(payload)
}

func (u *UseExtendedMasterSecret) unmarshalPayload(data []byte) error {
	if err := unmarshalEmptyExtensionPayload(data); err != nil {
		return err
	}
	u.Supported = true

	return nil
}
