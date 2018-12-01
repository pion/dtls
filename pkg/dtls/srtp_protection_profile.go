package dtls

type srtpProtectionProfile uint16

const (
	SRTP_AES128_CM_HMAC_SHA1_80 srtpProtectionProfile = 0x0001 // nolint
)

var srtpProtectionProfiles = map[srtpProtectionProfile]bool{
	SRTP_AES128_CM_HMAC_SHA1_80: true,
}
