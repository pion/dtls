// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package extension

// PostHandshakeAuth defines a DTLS 1.3 extension that is used to indicate
// that a client is willing to perform post-handshake authentication.
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.6
type PostHandshakeAuth struct {
	Enabled bool
}

// TypeValue returns the extension TypeValue.
func (p PostHandshakeAuth) TypeValue() TypeValue {
	return PostHandshakeAuthTypeValue
}

// Marshal encodes the extension.
func (p *PostHandshakeAuth) Marshal() ([]byte, error) {
	return marshalEmptyExtension(p.TypeValue(), p.Enabled)
}

// Unmarshal populates the extension from encoded data.
func (p *PostHandshakeAuth) Unmarshal(data []byte) error {
	payload, err := extensionPayload(data, p.TypeValue())
	if err != nil {
		return err
	}

	return p.unmarshalPayload(payload)
}

func (p *PostHandshakeAuth) unmarshalPayload(data []byte) error {
	if err := unmarshalEmptyExtensionPayload(data); err != nil {
		return err
	}
	p.Enabled = true

	return nil
}
