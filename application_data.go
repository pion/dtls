package main

// Application data messages are carried by the record layer and are
// fragmented, compressed, and encrypted based on the current connection
// state.  The messages are treated as transparent data to the record
// layer.
// https://tools.ietf.org/html/rfc5246#section-10
type applicationData struct {
}

func (a applicationData) contentType() contentType {
	return contentTypeApplicationData
}

func (a *applicationData) marshal() ([]byte, error) {
	return nil, nil
}

func (a *applicationData) unmarshal(data []byte) error {
	return nil
}
