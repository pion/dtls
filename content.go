package main

// https://tools.ietf.org/html/rfc4346#section-6.2.1
type contentType uint8

const (
	contentTypeChangeCipherSpec contentType = 20
	contentTypeAlert            contentType = 21
	contentTypeHandshake        contentType = 22
	contentTypeApplicationData  contentType = 23
)

type content interface {
	contentType() contentType
	marshal() ([]byte, error)
	unmarshal(data []byte) error
}
