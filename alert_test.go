package dtls

import (
	"reflect"
	"testing"
)

func TestAlert(t *testing.T) {
	for _, test := range []struct {
		Name               string
		Data               []byte
		Want               *alert
		WantUnmarshalError error
	}{
		{
			Name: "Valid Alert",
			Data: []byte{0x02, 0x0A},
			Want: &alert{
				alertLevel:       alertLevelFatal,
				alertDescription: alertUnexpectedMessage,
			},
		},
		{
			Name:               "Invalid alert length",
			Data:               []byte{0x00},
			Want:               &alert{},
			WantUnmarshalError: errBufferTooSmall,
		},
	} {
		a := &alert{}
		if err := a.Unmarshal(test.Data); err != test.WantUnmarshalError {
			t.Errorf("Unexpected Error %v: exp: %v got: %v", test.Name, test.WantUnmarshalError, err)
		} else if !reflect.DeepEqual(test.Want, a) {
			t.Errorf("%q alert.unmarshal: got %v, want %v", test.Name, a, test.Want)
		}

		if test.WantUnmarshalError != nil {
			return
		}

		data, marshalErr := a.Marshal()
		if marshalErr != nil {
			t.Errorf("Unexpected Error %v: got: %v", test.Name, marshalErr)
		} else if !reflect.DeepEqual(test.Data, data) {
			t.Errorf("%q alert.marshal: got % 02x, want % 02x", test.Name, data, test.Data)
		}
	}
}
