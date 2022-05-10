package dtls

import (
	"context"

	"github.com/pion/dtls/v2/pkg/protocol/alert"
)

// Parse received handshakes and return next FlightVal
type flightParser func(context.Context, flightConn, *State, *handshakeCache, *handshakeConfig) (FlightVal, *alert.Alert, error)

// Generate flights
type flightGenerator func(flightConn, *State, *handshakeCache, *handshakeConfig) ([]*packet, *alert.Alert, error)

func (f FlightVal) getFlightParser() (flightParser, error) {
	switch f {
	case Flight0:
		return flight0Parse, nil
	case Flight1:
		return flight1Parse, nil
	case Flight2:
		return flight2Parse, nil
	case Flight3:
		return flight3Parse, nil
	case Flight4:
		return flight4Parse, nil
	case Flight4b:
		return flight4bParse, nil
	case Flight5:
		return flight5Parse, nil
	case Flight5b:
		return flight5bParse, nil
	case Flight6:
		return flight6Parse, nil
	default:
		return nil, errInvalidFlight
	}
}

func (f FlightVal) getFlightGenerator() (gen flightGenerator, retransmit bool, err error) {
	switch f {
	case Flight0:
		return flight0Generate, true, nil
	case Flight1:
		return flight1Generate, true, nil
	case Flight2:
		// https://tools.ietf.org/html/rfc6347#section-3.2.1
		// HelloVerifyRequests must not be retransmitted.
		return flight2Generate, false, nil
	case Flight3:
		return flight3Generate, true, nil
	case Flight4:
		return flight4Generate, true, nil
	case Flight4b:
		return flight4bGenerate, true, nil
	case Flight5:
		return flight5Generate, true, nil
	case Flight5b:
		return flight5bGenerate, true, nil
	case Flight6:
		return flight6Generate, true, nil
	default:
		return nil, false, errInvalidFlight
	}
}
