// +build gofuzz

package dtls

import "fmt"

func partialHeaderMismatch(a, b RecordLayerHeader) bool {
	// Ignoring content length for now.
	a.ContentLen = b.ContentLen
	return a != b
}

func FuzzRecordLayer(data []byte) int {
	var r RecordLayer
	if err := r.Unmarshal(data); err != nil {
		return 0
	}
	buf, err := r.Marshal()
	if err != nil {
		return 1
	}
	if len(buf) == 0 {
		panic("zero buff") // nolint
	}
	var nr RecordLayer
	if err = nr.Unmarshal(data); err != nil {
		panic(err) // nolint
	}
	if partialHeaderMismatch(nr.RecordLayerHeader, r.RecordLayerHeader) {
		panic( // nolint
			fmt.Sprintf("header mismatch: %+v != %+v",
				nr.RecordLayerHeader, r.RecordLayerHeader,
			),
		)
	}

	return 1
}
