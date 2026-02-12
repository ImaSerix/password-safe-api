package service

import (
	"database/sql"
	"errors"
	"log/slog"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/repository"
	"github.com/google/uuid"
)

type SecretService interface {
	Add(userID uuid.UUID, key []byte, plaintext []byte) (*domain.Secret, error)
	GetByUser(userID uuid.UUID, key []byte) ([]*domain.DecryptedSecret, error)
}

type secretService struct {
	secrets repository.SecretRepository
	crypto  Crypto
}

func NewSecretService(sr repository.SecretRepository, c Crypto) *secretService {
	return &secretService{
		secrets: sr,
		crypto:  c,
	}
}

// Add creates and stores a new secret for a user
// It encrypts the plaintext using the provided key before storing
// Key is 32 bytes for ChaCha20-Poly1305 encryption
func (ss *secretService) Add(userID uuid.UUID, key []byte, plaintext []byte) (*domain.Secret, error) {
	op := "secretService.Add"

	var secret domain.Secret
	secret.UserID = userID

	if len(key) == 0 {
		return nil, ErrInvalidKey
	}

	if userID == uuid.Nil {
		return nil, ErrInvalidUserID
	}

	encryptedData, nonce, err := ss.crypto.Encrypt(key, plaintext)
	if err != nil {
		slog.Error("encrypt secret failed", "op", op, "err", err.Error())
		return nil, ErrInvalidKey
	}
	secret.Nonce = nonce
	secret.EncryptedData = encryptedData

	created, err := ss.secrets.Create(&secret)
	if err != nil {
		slog.Error("create secret failed", "op", op, "err", err.Error())
		return nil, ErrInternal
	}
	return created, nil
}

// GetByUser retrieves all secrets for a user and decrypts them
// Transforms *domain.Secrets from repository to *domain.DecryptedSecret, by decrypting data
// Key is 32 bytes for ChaCha20-Poly1305 encryption
func (ss *secretService) GetByUser(userID uuid.UUID, key []byte) (decSecrets []*domain.DecryptedSecret, err error) {
	op := "secretService.GetByUser"

	if len(key) == 0 {
		return nil, ErrInvalidKey
	}

	if userID == uuid.Nil {
		return nil, ErrInvalidUserID
	}

	secrets, err := ss.secrets.FindByUserID(userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		slog.Error("find secret by user failed", "op", op, "err", err.Error())
		return nil, ErrInternal
	}
	for _, secret := range secrets {
		var decSecret domain.DecryptedSecret
		decSecret.UUID = secret.UUID
		decSecret.CreatedAt = secret.CreatedAt

		plaintext, err := ss.crypto.Decrypt(key, secret.EncryptedData, secret.Nonce)
		if err != nil {
			slog.Error("decrypt secret by user failed", "op", op, "err", err.Error())
			return decSecrets, ErrInvalidKey
		}
		decSecret.Data = plaintext
		decSecrets = append(decSecrets, &decSecret)
	}
	return decSecrets, nil
}
