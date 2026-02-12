package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func (i *Impl) Encrypt(key, plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt: %w", err)
	}

	nonce, err = i.NewNonce(24)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt: %w", err)
	}

	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func (i *Impl) Decrypt(key, ciphertext, nonce []byte) (plaintext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	plaintext, err = aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
