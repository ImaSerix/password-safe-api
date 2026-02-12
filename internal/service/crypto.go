package service

type Crypto interface {
	Encrypt(key, plaintext []byte) (ciphertext []byte, nonce []byte, err error)
	Decrypt(key, ciphertext, nonce []byte) (plaintext []byte, err error)

	DeriveKey(password string, salt []byte) []byte
	HashPassword(password string, salt []byte) []byte
	NewSalt(size int) ([]byte, error)
	NewNonce(size int) ([]byte, error)
}
