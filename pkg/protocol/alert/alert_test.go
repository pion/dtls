// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package alert

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlert(t *testing.T) {
	for _, test := range []struct {
		Name               string
		Data               []byte
		Want               *Alert
		WantUnmarshalError error
	}{
		{
			Name: "Valid Alert",
			Data: []byte{0x02, 0x0A},
			Want: &Alert{
				Level:       Fatal,
				Description: UnexpectedMessage,
			},
		},
		{
			Name:               "Invalid alert length",
			Data:               []byte{0x00},
			Want:               &Alert{},
			WantUnmarshalError: errBufferTooSmall,
		},
	} {
		a := &Alert{}
		assert.ErrorIs(t, a.Unmarshal(test.Data), test.WantUnmarshalError)
		assert.Equal(t, test.Want, a)

		if test.WantUnmarshalError != nil {
			return
		}

		data, marshalErr := a.Marshal()
		assert.NoError(t, marshalErr)
		assert.Equal(t, test.Data, data)
	}
}
