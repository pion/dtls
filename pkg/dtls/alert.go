package dtls

import "fmt"

type alertLevel byte

const (
	alertLevelWarning alertLevel = 1
	alertLevelFatal              = 2
)

func (a alertLevel) String() string {
	switch a {
	case alertLevelWarning:
		return "LevelWarning"
	case alertLevelFatal:
		return "LevelFatal"
	default:
		return "Invalid alert level"
	}
}

type alertDescription byte

const (
	alertCloseNotify            alertDescription = 0
	alertUnexpectedMessage                       = 10
	alertBadRecordMac                            = 20
	alertDecryptionFailed                        = 21
	alertRecordOverflow                          = 22
	alertDecompressionFailure                    = 30
	alertHandshakeFailure                        = 40
	alertNoCertificate                           = 41
	alertBadCertificate                          = 42
	alertUnsupportedCertificate                  = 43
	alertCertificateRevoked                      = 44
	alertCertificateExpired                      = 45
	alertCertificateUnknown                      = 46
	alertIllegalParameter                        = 47
	alertUnknownCA                               = 48
	alertAccessDenied                            = 49
	alertDecodeError                             = 50
	alertDecryptError                            = 51
	alertExportRestriction                       = 60
	alertProtocolVersion                         = 70
	alertInsufficientSecurity                    = 71
	alertInternalError                           = 80
	alertUserCanceled                            = 90
	alertNoRenegotiation                         = 100
	alertUnsupportedExtension                    = 110
)

func (a alertDescription) String() string {
	switch a {
	case alertCloseNotify:
		return "CloseNotify"
	case alertUnexpectedMessage:
		return "UnexpectedMessage"
	case alertBadRecordMac:
		return "BadRecordMac"
	case alertDecryptionFailed:
		return "DecryptionFailed"
	case alertRecordOverflow:
		return "RecordOverflow"
	case alertDecompressionFailure:
		return "DecompressionFailure"
	case alertHandshakeFailure:
		return "HandshakeFailure"
	case alertNoCertificate:
		return "NoCertificate"
	case alertBadCertificate:
		return "BadCertificate"
	case alertUnsupportedCertificate:
		return "UnsupportedCertificate"
	case alertCertificateRevoked:
		return "CertificateRevoked"
	case alertCertificateExpired:
		return "CertificateExpired"
	case alertCertificateUnknown:
		return "CertificateUnknown"
	case alertIllegalParameter:
		return "IllegalParameter"
	case alertUnknownCA:
		return "UnknownCA"
	case alertAccessDenied:
		return "AccessDenied"
	case alertDecodeError:
		return "DecodeError"
	case alertDecryptError:
		return "DecryptError"
	case alertExportRestriction:
		return "ExportRestriction"
	case alertProtocolVersion:
		return "ProtocolVersion"
	case alertInsufficientSecurity:
		return "InsufficientSecurity"
	case alertInternalError:
		return "InternalError"
	case alertUserCanceled:
		return "UserCanceled"
	case alertNoRenegotiation:
		return "NoRenegotiation"
	case alertUnsupportedExtension:
		return "UnsupportedExtension"
	default:
		return "Invalid alert description"
	}
}

// One of the content types supported by the TLS record layer is the
// alert type.  Alert messages convey the severity of the message
// (warning or fatal) and a description of the alert.  Alert messages
// with a level of fatal result in the immediate termination of the
// connection.  In this case, other connections corresponding to the
// session may continue, but the session identifier MUST be invalidated,
// preventing the failed session from being used to establish new
// connections.  Like other messages, alert messages are encrypted and
// compressed, as specified by the current connection state.
// https://tools.ietf.org/html/rfc5246#section-7.2
type alert struct {
	alertLevel       alertLevel
	alertDescription alertDescription
}

func (a alert) contentType() contentType {
	return contentTypeAlert
}

func (a *alert) marshal() ([]byte, error) {
	return []byte{byte(a.alertLevel), byte(a.alertDescription)}, nil
}

func (a *alert) unmarshal(data []byte) error {
	if len(data) != 2 {
		return errBufferTooSmall
	}

	a.alertLevel = alertLevel(data[0])
	a.alertDescription = alertDescription(data[1])
	return nil
}

func (a *alert) String() string {
	return fmt.Sprintf("Alert %s: %s", a.alertLevel, a.alertDescription)
}
