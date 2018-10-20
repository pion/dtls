package dtls

type compressionMethodID byte

const (
	compressionMethodNull compressionMethodID = 0
)

type compressionMethod struct {
	id compressionMethodID
}

var compressionMethods = map[compressionMethodID]*compressionMethod{
	compressionMethodNull: {id: compressionMethodNull},
}

var defaultCompressionMethods = []*compressionMethod{
	compressionMethods[compressionMethodNull],
}
