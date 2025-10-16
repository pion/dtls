// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

type flightVal13 uint8

/*

Full DTLS Handshake (with Cookie Exchange):

Client                                            Server

                                                           +----------+
 ClientHello                                               | Flight 1 |
                       -------->                           +----------+

                                                           +----------+
                       <--------        HelloRetryRequest  | Flight 2 |
                                         + cookie          +----------+


                                                           +----------+
ClientHello                                                | Flight 3 |
 + cookie              -------->                           +----------+



                                              ServerHello
                                    {EncryptedExtensions}  +----------+
                                    {CertificateRequest*}  | Flight 4 |
                                           {Certificate*}  +----------+
                                     {CertificateVerify*}
                                               {Finished}
                       <--------      [Application Data*]



 {Certificate*}                                            +----------+
 {CertificateVerify*}                                      | Flight 5 |
 {Finished}            -------->                           +----------+
 [Application Data]
                                                           +----------+
                       <--------                    [ACK]  | Flight 6 |
                                      [Application Data*]  +----------+

 [Application Data]    <------->      [Application Data]




Resumption and PSK Handshake (without Cookie Exchange):

Client                                            Server

 ClientHello                                              +-----------+
  + pre_shared_key                                        | Flight 3a |
  + psk_key_exchange_modes                                +-----------+
  + key_share*         -------->


                                             ServerHello
                                        + pre_shared_key  +-----------+
                                            + key_share*  | Flight 4a |
                                   {EncryptedExtensions}  +-----------+
                       <--------              {Finished}
                                     [Application Data*]
                                                          +-----------+
 {Finished}            -------->                          | Flight 5a |
 [Application Data*]                                      +-----------+

                                                          +-----------+
                       <--------                   [ACK]  | Flight 6a |
                                     [Application Data*]  +-----------+

 [Application Data]    <------->      [Application Data]


Zero-RTT Handshake:

Client                                            Server

 ClientHello
  + early_data
  + psk_key_exchange_modes                                +-----------+
  + key_share*                                            | Flight 3b |
  + pre_shared_key                                        +-----------+
 (Application Data*)     -------->

                                             ServerHello
                                        + pre_shared_key
                                            + key_share*  +-----------+
                                   {EncryptedExtensions}  | Flight 4b |
                                              {Finished}  +-----------+
                       <--------     [Application Data*]


                                                          +-----------+
 {Finished}            -------->                          | Flight 5b |
 [Application Data*]                                      +-----------+

                                                          +-----------+
                       <--------                   [ACK]  | Flight 6b |
                                     [Application Data*]  +-----------+

 [Application Data]    <------->      [Application Data]


NewSessionTicket Message:

Client                                            Server

                                                          +-----------+
                       <--------       [NewSessionTicket] | Flight 4c |
                                                          +-----------+

                                                          +-----------+
[ACK]                  -------->                          | Flight 5c |
                                                          +-----------+
*/

const (
	flight13_0 flightVal13 = iota + 1
	flight13_1
	flight13_2
	flight13_3
	flight13_3a
	flight13_3b
	flight13_4
	flight13_4a
	flight13_4b
	flight13_4c
	flight13_5
	flight13_5a
	flight13_5b
	flight13_5c
	flight13_6
	flight13_6a
	flight13_6b
)

func (f flightVal13) String() string { //nolint:cyclop
	switch f {
	case flight13_0:
		return "Flight13 0"
	case flight13_1:
		return "Flight13 1"
	case flight13_2:
		return "Flight13 2"
	case flight13_3:
		return "Flight13 3"
	case flight13_3a:
		return "Flight13 3a"
	case flight13_3b:
		return "Flight13 3b"
	case flight13_4:
		return "Flight13 4"
	case flight13_4a:
		return "Flight13 4a"
	case flight13_4b:
		return "Flight13 4b"
	case flight13_4c:
		return "Flight13 4c"
	case flight13_5:
		return "Flight13 5"
	case flight13_5a:
		return "Flight13 5a"
	case flight13_5b:
		return "Flight13 5b"
	case flight13_5c:
		return "Flight13 5c"
	case flight13_6:
		return "Flight13 6"
	case flight13_6a:
		return "Flight13 6a"
	case flight13_6b:
		return "Flight13 6b"
	default:
		return "Invalid Flight"
	}
}

func (f flightVal13) isLastSendFlight() bool {
	return f == flight13_6 || f == flight13_6a || f == flight13_6b || f == flight13_5c
}

func (f flightVal13) isLastRecvFlight() bool {
	return f == flight13_5 || f == flight13_5a || f == flight13_5b || f == flight13_4c
}
