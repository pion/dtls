package dtls

import "sync"

/*
  DTLS messages are grouped into a series of message flights, according
  to the diagrams below.  Although each flight of messages may consist
  of a number of messages, they should be viewed as monolithic for the
  purpose of timeout and retransmission.
  https://tools.ietf.org/html/rfc4347#section-4.2.4
  Client                                          Server
  ------                                          ------

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

*/

type flightVal uint8

const (
	flight1 flightVal = iota + 1
	flight2
	flight3
	flight4
	flight5
	flight6
)

type flight struct {
	sync.RWMutex
	val flightVal
}

func newFlight(isClient bool) flight {
	val := flight2
	if isClient {
		val = flight1
	}
	return flight{val: val}
}

func (f *flight) get() flightVal {
	f.RLock()
	defer f.RUnlock()
	return f.val
}

func (f *flight) set(val flightVal) error {
	f.RLock()
	defer f.RUnlock()
	// TODO ensure no invalid transitions
	f.val = val
	return nil
}
