package dtls

// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
type extensionValue uint16

const (
	extensionSupportedGroupsValue extensionValue = 10
	extensionUseSRTPValue                        = 14
)

type extension interface {
	marshal() ([]byte, error)
	unmarshal(data []byte) error

	extensionValue() extensionValue
}
