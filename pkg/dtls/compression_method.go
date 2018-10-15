package dtls

type compressionMethodID byte

const (
	compressionMethodNull compressionMethodID = 0
)

type compressionMethod struct {
}

var compressionMethods = map[compressionMethodID]*compressionMethod{
	compressionMethodNull: {},
}
