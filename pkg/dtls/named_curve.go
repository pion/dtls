package dtls

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type namedCurve uint16

const (
	namedCurveX25519 namedCurve = 0x001d
)

var namedCurves = map[namedCurve]bool{
	namedCurveX25519: true,
}
