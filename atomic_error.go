package dtls

import "sync"

type atomicError struct {
	mu  sync.Mutex
	val error
}

func (a *atomicError) store(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.val = err
}

func (a *atomicError) load() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.val
}
