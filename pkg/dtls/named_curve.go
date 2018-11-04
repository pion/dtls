package dtls

// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
type namedCurve uint16

const (
	namedCurveP256 namedCurve = 23
)

var namedCurves = map[namedCurve]bool{
	namedCurveP256: true,
}
