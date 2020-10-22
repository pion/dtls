package dtls

type packet struct {
	record                   *RecordLayer
	shouldEncrypt            bool
	resetLocalSequenceNumber bool
}
