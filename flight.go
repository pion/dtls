package dtls

/*
  DTLS messages are grouped into a series of message flights, according
  to the diagrams below.  Although each flight of messages may consist
  of a number of messages, they should be viewed as monolithic for the
  purpose of timeout and retransmission.
  https://tools.ietf.org/html/rfc4347#section-4.2.4

  Message flights for full handshake:

  Client                                          Server
  ------                                          ------
                                      Waiting                 Flight 0

  ClientHello             -------->                           Flight 1

                          <-------    HelloVerifyRequest      Flight 2

  ClientHello              -------->                           Flight 3

                                             ServerHello    \
                                            Certificate*     \
                                      ServerKeyExchange*      Flight 4
                                     CertificateRequest*     /
                          <--------      ServerHelloDone    /

  Certificate*                                              \
  ClientKeyExchange                                          \
  CertificateVerify*                                          Flight 5
  [ChangeCipherSpec]                                         /
  Finished                -------->                         /

                                      [ChangeCipherSpec]    \ Flight 6
                          <--------             Finished    /

  Message flights for session-resuming handshake (no cookie exchange):

  Client                                          Server
  ------                                          ------
                                      Waiting                 Flight 0

  ClientHello             -------->                           Flight 1

                                             ServerHello    \
                                      [ChangeCipherSpec]      Flight 4b
                          <--------             Finished    /

  [ChangeCipherSpec]                                        \ Flight 5b
  Finished                -------->                         /

                                      [ChangeCipherSpec]    \ Flight 6
                          <--------             Finished    /
*/

type FlightVal uint8

const (
	Flight0 FlightVal = iota + 1
	Flight1
	Flight2
	Flight3
	Flight4
	Flight4b
	Flight5
	Flight5b
	Flight6
)

func (f FlightVal) String() string {
	switch f {
	case Flight0:
		return "Flight 0"
	case Flight1:
		return "Flight 1"
	case Flight2:
		return "Flight 2"
	case Flight3:
		return "Flight 3"
	case Flight4:
		return "Flight 4"
	case Flight4b:
		return "Flight 4b"
	case Flight5:
		return "Flight 5"
	case Flight5b:
		return "Flight 5b"
	case Flight6:
		return "Flight 6"
	default:
		return "Invalid Flight"
	}
}

func (f FlightVal) isLastSendFlight() bool {
	return f == Flight6 || f == Flight5b
}

func (f FlightVal) isLastRecvFlight() bool {
	return f == Flight5 || f == Flight4b
}
