package dtls

// Session store data needed in resumption
type Session struct {
	// ID store session id
	ID []byte
	// Secret store session master secret
	Secret []byte
	// Addr store remote endpoint's address
	Addr string
}

type SessionStore interface {
	// Set save a session.
	// For client, use remove address as key.
	// For server, session id.
	Set(s *Session, isClient bool)
	// Get fetch a session by id.
	Get(id []byte) *Session
	// GetByAddr fetch a session by remote server address.
	GetByAddr(addr string) *Session
	// Del clean saved session
	Del(id []byte)
}
