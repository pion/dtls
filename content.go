package dtls

// https://tools.ietf.org/html/rfc4346#section-6.2.1
type ContentType uint8

const (
	ContentTypeChangeCipherSpec ContentType = 20
	ContentTypeAlert            ContentType = 21
	ContentTypeHandshake        ContentType = 22
	ContentTypeApplicationData  ContentType = 23
)

type Content interface {
	ContentType() ContentType
	Marshal() ([]byte, error)
	Unmarshal(data []byte) error
}
