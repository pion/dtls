package main

import "errors"

var (
	errInvalidCipherSpec       = errors.New("dtls: cipher spec invalid")
	errDTLSPacketInvalidLength = errors.New("dtls: packet is too short")
	errInvalidContentType      = errors.New("dtls: invalid content type")
)
