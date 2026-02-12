package crypto

import "crypto/rand"

func (i *Impl) RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func (i *Impl) NewSalt(size int) ([]byte, error) {
	return i.RandomBytes(size)
}

func (i *Impl) NewNonce(size int) ([]byte, error) {
	return i.RandomBytes(size)
}
