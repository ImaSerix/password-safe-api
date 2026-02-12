package service_test

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/service"
	"github.com/google/uuid"
)

type fakeSecretRepository struct {
	secrets []*domain.Secret
	err     error
	called  bool
}

func (fsr *fakeSecretRepository) Create(u *domain.Secret) (*domain.Secret, error) {
	fsr.called = true
	if fsr.err != nil {
		return nil, fsr.err
	}

	fsr.secrets = append(fsr.secrets, u)
	u.UUID = uuid.New()
	u.CreatedAt = time.Now()
	return u, nil
}
func (fsr *fakeSecretRepository) FindByID(id uuid.UUID) (*domain.Secret, error) {
	fsr.called = true
	if fsr.err != nil {
		return nil, fsr.err
	}

	for _, secret := range fsr.secrets {
		if secret.UUID == id {
			return secret, nil
		}
	}
	return nil, fmt.Errorf("finding secret %s: no such secret", id)
}
func (fsr *fakeSecretRepository) FindByUserID(userID uuid.UUID) (secrets []*domain.Secret, err error) {
	fsr.called = true
	if fsr.err != nil {
		return nil, fsr.err
	}

	for _, secret := range fsr.secrets {
		if secret.UserID == userID {
			secrets = append(secrets, secret)
		}
	}
	return secrets, nil
}

type fakeSecretCrypto struct {
	err error
}

func (fc *fakeSecretCrypto) Encrypt(key, plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	if fc.err != nil {
		return nil, nil, fc.err
	}
	return []byte("crypted text"), []byte("Good nonce"), nil
}

func (fc *fakeSecretCrypto) Decrypt(key, ciphertext, nonce []byte) (plaintext []byte, err error) {
	if fc.err != nil {
		return nil, fc.err
	}
	return []byte("plain text"), nil
}

func (fc *fakeSecretCrypto) DeriveKey(password string, salt []byte) []byte {
	return nil
}

func (fc *fakeSecretCrypto) HashPassword(password string, salt []byte) []byte {
	return nil
}

func (fc *fakeSecretCrypto) NewSalt(size int) ([]byte, error) {
	return nil, nil
}
func (fc *fakeSecretCrypto) NewNonce(size int) ([]byte, error) {
	return nil, nil
}

func TestSecretService_Add_Validation(t *testing.T) {
	tests := []struct {
		name   string
		key    []byte
		userID uuid.UUID
		cErr   error
		expErr error
	}{
		{"simple", []byte("-xKHqZZEbnk7w5aWRnv!CQG7VG_!Dgf#"), uuid.New(), nil, nil},
		{"no userID", []byte("-xKHqZZEbnk7w5aWRnv!CQG7VG_!Dgf#"), uuid.UUID{}, nil, service.ErrInvalidUserID},
		{"short key", []byte("-xKHqZZEbnk7w5aWRnv"), uuid.New(), errors.New("crypto error"), service.ErrInvalidKey},
		{"no key", nil, uuid.New(), nil, service.ErrInvalidKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeSecretRepository{called: false}
			secretService := service.NewSecretService(repo, &fakeSecretCrypto{err: tt.cErr})
			secret, err := secretService.Add(tt.userID, tt.key, []byte("test data"))
			if !errors.Is(err, tt.expErr) {
				t.Fatalf("expected error %v, got %v", tt.expErr, err)
			}
			if tt.expErr != nil && repo.called {
				t.Fatal("repo should not be called on validation error")
			}
			if tt.expErr != nil && secret != nil {
				t.Fatalf("expected nil secret on error, got %+v", secret)
			}
			if err == nil && secret == nil {
				t.Fatal("expected secret, got nil")
			}
		})
	}
}

func TestSecretService_Add_Success(t *testing.T) {
	tests := []struct {
		name   string
		key    []byte
		userID uuid.UUID
	}{
		{"1. happy path", []byte("-xKHqZZEbnk7w5aWRnv!CQG7VG_!Dgf#"), uuid.New()},
		{"2. happy path", []byte("-xKHqZZEbnk7w5aWRnv!CQG7VG_!Dgf#"), uuid.New()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretService := service.NewSecretService(&fakeSecretRepository{}, &fakeSecretCrypto{})
			secret, err := secretService.Add(tt.userID, tt.key, []byte("test data"))
			if err != nil {
				t.Fatal("expected no error")
			}
			if secret == nil {
				t.Fatal("expected secret got nil")
			}
			if secret.UserID != tt.userID {
				t.Fatalf("expected userID %s got %s", tt.userID, secret.UserID)
			}
			if len(secret.Nonce) == 0 {
				t.Fatal("expected non empty nonce")
			}
			if bytes.Equal(secret.EncryptedData, []byte("test data")) {
				t.Fatal("data isn't encrypted")
			}
		})
	}
}

func TestSecretService_Add_RepoError(t *testing.T) {
	repo := &fakeSecretRepository{err: errors.New("db down")}
	s := service.NewSecretService(repo, &fakeSecretCrypto{})

	_, err := s.Add(uuid.New(), []byte("valid key"), []byte("data"))
	if !errors.Is(err, service.ErrInternal) {
		t.Fatal("expected internal error")
	}
}

func TestSecretService_GetByUser_Validation(t *testing.T) {
	userID := uuid.New()
	s := []*domain.Secret{
		{UUID: uuid.New(), UserID: userID, EncryptedData: []byte("encrypted data"), Nonce: []byte("nonce"), CreatedAt: time.Now()},
		{UUID: uuid.New(), UserID: userID, EncryptedData: []byte("encrypted data"), Nonce: []byte("nonce"), CreatedAt: time.Now()},
		{UUID: uuid.New(), UserID: userID, EncryptedData: []byte("encrypted data"), Nonce: []byte("nonce"), CreatedAt: time.Now()},
		{UUID: uuid.New(), UserID: uuid.New(), EncryptedData: []byte("encrypted data"), Nonce: []byte("nonce"), CreatedAt: time.Now()},
	}

	tests := []struct {
		name   string
		key    []byte
		userID uuid.UUID
		rErr   error
		cErr   error
		expErr error
	}{
		{"simple", []byte("-xKHqZZEbnk7w5aWRnv!CQG7VG_!Dgf#"), userID, nil, nil, nil},
		{"no userID", []byte("-xKHqZZEbnk7w5aWRnv!CQG7VG_!Dgf#"), uuid.UUID{}, nil, nil, service.ErrInvalidUserID},
		{"no secrets", []byte("-xKHqZZEbnk7w5aWRnv!CQG7VG_!Dgf#"), uuid.New(), sql.ErrNoRows, nil, service.ErrNotFound},
		{"short key", []byte("-xKHqZZEbnk7w5aWRnv"), userID, nil, errors.New("crypto error"), service.ErrInvalidKey},
		{"no key", nil, uuid.New(), nil, nil, service.ErrInvalidKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeSecretRepository{secrets: s, err: tt.rErr}
			secretService := service.NewSecretService(repo, &fakeSecretCrypto{err: tt.cErr})
			decSecret, err := secretService.GetByUser(tt.userID, tt.key)
			if !errors.Is(err, tt.expErr) {
				t.Fatalf("expected error %v, got %v", tt.expErr, err)
			}
			if tt.expErr != nil && decSecret != nil {
				t.Fatalf("expected nil decrypted secret on error, got %+v", decSecret)
			}
			if err == nil && decSecret == nil {
				t.Fatal("expected decrypted secret, got nil")
			}
		})
	}
}

func TestSecretService_GetByUser_Success(t *testing.T) {
	userID1 := uuid.New()
	userID2 := uuid.New()
	s := []*domain.Secret{
		{UUID: uuid.New(), UserID: userID1, EncryptedData: []byte("encrypted data"), Nonce: []byte("nonce"), CreatedAt: time.Now()},
		{UUID: uuid.New(), UserID: userID1, EncryptedData: []byte("encrypted data"), Nonce: []byte("nonce"), CreatedAt: time.Now()},
		{UUID: uuid.New(), UserID: userID1, EncryptedData: []byte("encrypted data"), Nonce: []byte("nonce"), CreatedAt: time.Now()},
		{UUID: uuid.New(), UserID: userID2, EncryptedData: []byte("encrypted data"), Nonce: []byte("nonce"), CreatedAt: time.Now()},
	}

	tests := []struct {
		name   string
		key    []byte
		userID uuid.UUID
		rErr   error
		cErr   error
		expErr error
	}{
		{"1. Happy path", []byte("-xKHqZZEbnk7w5aWRnv!CQG7VG_!Dgf#"), userID1, nil, nil, nil},
		{"2. Happy path", []byte("-xKHqZZEbnk7w5aWRnv!CQG7VG_!Dgf#"), userID2, nil, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretService := service.NewSecretService(&fakeSecretRepository{secrets: s}, &fakeSecretCrypto{})
			decSecrets, err := secretService.GetByUser(tt.userID, tt.key)
			if err != nil {
				t.Fatal("expected no error")
			}
			if len(decSecrets) == 0 {
				t.Fatal("expected decrypted secrets got empty slice")
			}
			if !bytes.Equal(decSecrets[0].Data, []byte("plain text")) {
				t.Fatal("expected decrypted data")
			}
		})
	}
}

func TestSecretService_GetByUser_RepoError(t *testing.T) {
	repo := &fakeSecretRepository{err: errors.New("db down")}
	s := service.NewSecretService(repo, &fakeSecretCrypto{})

	_, err := s.GetByUser(uuid.New(), []byte("valid key"))
	if !errors.Is(err, service.ErrInternal) {
		t.Fatal("expected internal error")
	}
}
