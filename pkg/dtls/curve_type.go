package dtls

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-10
type ellipticCurveType uint16

const (
	ellipticCurveTypeNamedCurve ellipticCurveType = 0x03
)

var ellipticCurveTypes = map[ellipticCurveType]bool{
	ellipticCurveTypeNamedCurve: true,
}
