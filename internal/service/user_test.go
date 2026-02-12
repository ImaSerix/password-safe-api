package service_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/repository"
	"github.com/ImaSerix/password-safe-api/internal/service"
	"github.com/google/uuid"
)

type fakeUserRepository struct {
	users  []*domain.User
	err    error
	called bool
}

func (fur *fakeUserRepository) Create(u *domain.User) (*domain.User, error) {
	fur.called = true
	if fur.err != nil {
		return nil, fur.err
	}

	u.UUID = uuid.New()
	u.PasswordHash = []byte(u.PasswordHash)
	u.Salt = []byte("niceSalt")
	u.EncSalt = []byte("niceEncSalt")
	fur.users = append(fur.users, u)
	return u, nil
}
func (fur *fakeUserRepository) FindByID(id uuid.UUID) (*domain.User, error) {
	fur.called = true
	if fur.err != nil {
		return nil, fur.err
	}

	for _, user := range fur.users {
		if user.UUID == id {
			return user, nil
		}
	}
	return nil, sql.ErrNoRows
}
func (fur *fakeUserRepository) FindByUsername(username string) (*domain.User, error) {
	fur.called = true
	if fur.err != nil {
		return nil, fur.err
	}

	for _, user := range fur.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, sql.ErrNoRows
}

type fakeUserCrypto struct {
	err error
}

func (fuc *fakeUserCrypto) Encrypt(key, plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	return nil, nil, nil
}
func (fuc *fakeUserCrypto) Decrypt(key, ciphertext, nonce []byte) (plaintext []byte, err error) {
	return nil, nil
}

func (fuc *fakeUserCrypto) DeriveKey(password string, salt []byte) []byte {
	return nil
}

func (fuc *fakeUserCrypto) HashPassword(password string, salt []byte) []byte {
	return []byte(password)
}

func (fuc *fakeUserCrypto) NewSalt(size int) ([]byte, error) {
	if fuc.err != nil {
		return nil, fuc.err
	}
	return []byte("nice salt"), nil
}
func (fuc *fakeUserCrypto) NewNonce(size int) ([]byte, error) {
	if fuc.err != nil {
		return nil, fuc.err
	}
	return []byte("nice nonce"), nil
}

func TestUserService_Register_Validation(t *testing.T) {

	tests := []struct {
		name     string
		username string
		password string
		expErr   error
	}{
		{name: "simple", username: "goodGuy", password: "nicePassword", expErr: nil},
		{name: "empty username", username: "", password: "nicePassword", expErr: service.ErrInvalidUsername},
		{name: "empty password", username: "goodGuy", password: "", expErr: service.ErrInvalidPassword},
		{name: "long username", username: strings.Repeat("veryLongUsername", 1_000), password: "goodPassword", expErr: service.ErrInvalidUsername},
		{name: "short password", username: "goodGuy", password: "badPas", expErr: service.ErrInvalidPassword},
		{name: "long password", username: "goodGuy", password: strings.Repeat("veryLongPassword", 1_000), expErr: service.ErrInvalidPassword},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeUserRepository{}
			userService := service.NewUserService(repo, &fakeUserCrypto{})
			user, err := userService.Register(tt.username, tt.password)
			if !errors.Is(err, tt.expErr) {
				t.Fatalf("expected error %v, got %v", tt.expErr, err)
			}
			if tt.expErr != nil && repo.called {
				t.Fatal("repo should not be called on validation error")
			}
			if tt.expErr != nil && user != nil {
				t.Fatalf("expected nil user on error, got %+v", user)
			}
			if err == nil && user == nil {
				t.Fatal("expected user, got nil")
			}
		})
	}
}

func TestUserService_Register_Success(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		expErr   error
	}{
		{name: "1. Happy path", username: "goodGuy", password: "nicePassword", expErr: nil},
		{name: "2. Happy path", username: "goodGirl", password: "v$ryG00dP@ssw0rd", expErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeUserRepository{}
			userService := service.NewUserService(repo, &fakeUserCrypto{})
			user, err := userService.Register(tt.username, tt.password)
			if err != nil {
				t.Fatal("expected no error")
			}
			if user == nil {
				t.Fatal("expected user got nil")
			}
			if user.Username != tt.username {
				t.Fatalf("expected username %s got %s", tt.username, user.Username)
			}
			if len(user.PasswordHash) == 0 {
				t.Fatal("expected non empty passwordHash")
			}
			if len(user.Salt) == 0 {
				t.Fatal("expected non empty password salt")
			}
			if len(user.EncSalt) == 0 {
				t.Fatal("expected non empty key salt")
			}
		})
	}
}

func TestUserService_Register_RepoError(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		expErr   error
		rErr     error
	}{
		{name: "unique username", username: "goodGuy", password: "nicePassword", rErr: repository.ErrAlreadyExists, expErr: service.ErrUsernameTaken},
		{name: "db down", username: "goodGuy", password: "nicePassword", rErr: errors.New("db down"), expErr: service.ErrInternal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeUserRepository{
				err: tt.rErr,
			}
			userService := service.NewUserService(repo, &fakeUserCrypto{})
			user, err := userService.Register(tt.username, tt.password)
			if !errors.Is(err, tt.expErr) {
				t.Fatalf("expected error %v, got %v", tt.expErr, err)
			}
			if user != nil {
				t.Fatalf("expected nil user on error, got %+v", user)
			}
		})
	}
}

func TestUserService_Authenticate_Validation(t *testing.T) {

	tests := []struct {
		name     string
		username string
		password string
		expErr   error
	}{
		{name: "simple", username: "goodGuy", password: "nicePassword", expErr: nil},
		{name: "empty username", username: "", password: "nicePassword", expErr: service.ErrInvalidCredentials},
		{name: "empty password", username: "goodGuy", password: "", expErr: service.ErrInvalidCredentials},
		{name: "long username", username: strings.Repeat("veryLongUsername", 1_000), password: "goodPassword", expErr: service.ErrInvalidCredentials},
		{name: "long password", username: "goodGuy", password: strings.Repeat("veryLongPassword", 1_000), expErr: service.ErrInvalidCredentials},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeUserRepository{
				users: []*domain.User{
					{UUID: uuid.New(), Username: "goodGuy", PasswordHash: []byte("nicePassword"), Salt: []byte("niceSalt"), EncSalt: []byte("niceEncSalt")},
				},
			}
			userService := service.NewUserService(repo, &fakeUserCrypto{})
			user, err := userService.Authenticate(tt.username, tt.password)
			if !errors.Is(err, tt.expErr) {
				t.Fatalf("expected error %v, got %v", tt.expErr, err)
			}
			if tt.expErr != nil && repo.called {
				t.Fatal("repo should not be called on validation error")
			}
			if tt.expErr != nil && user != nil {
				t.Fatalf("expected nil user on error, got %+v", user)
			}
			if err == nil && user == nil {
				t.Fatal("expected user, got nil")
			}
		})
	}
}

func TestUserService_Authenticate_Success(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		expErr   error
	}{
		{name: "1. Happy path", username: "goodGuy", password: "nicePassword", expErr: nil},
		{name: "2. Happy path", username: "goodGirl", password: "v$ryG00dP@ssw0rd", expErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeUserRepository{
				users: []*domain.User{
					{UUID: uuid.New(), Username: "goodGuy", PasswordHash: []byte("nicePassword"), Salt: []byte("niceSalt"), EncSalt: []byte("niceEncSalt")},
					{UUID: uuid.New(), Username: "goodGirl", PasswordHash: []byte("v$ryG00dP@ssw0rd"), Salt: []byte("niceSalt"), EncSalt: []byte("niceEncSalt")},
				},
			}
			userService := service.NewUserService(repo, &fakeUserCrypto{})
			user, err := userService.Authenticate(tt.username, tt.password)
			if err != nil {
				t.Fatal("expected no error")
			}
			if user == nil {
				t.Fatal("expected user got nil")
			}
			if user.Username != tt.username {
				t.Fatalf("expected username %s got %s", tt.username, user.Username)
			}
			if len(user.PasswordHash) == 0 {
				t.Fatal("expected non empty passwordHash")
			}
			if len(user.Salt) == 0 {
				t.Fatal("expected non empty password salt")
			}
			if len(user.EncSalt) == 0 {
				t.Fatal("expected non empty key salt")
			}
		})
	}
}

func TestUserService_Authenticate_RepoError(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		expErr   error
		rErr     error
	}{
		{name: "db down", username: "goodGuy", password: "nicePassword", rErr: errors.New("db down"), expErr: service.ErrInternal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeUserRepository{
				err: tt.rErr,
			}
			userService := service.NewUserService(repo, &fakeUserCrypto{})
			user, err := userService.Authenticate(tt.username, tt.password)
			if !errors.Is(err, tt.expErr) {
				t.Fatalf("expected error %v, got %v", tt.expErr, err)
			}
			if user != nil {
				t.Fatalf("expected nil user on error, got %+v", user)
			}
		})
	}
}
