package service

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"log/slog"
	"strings"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/repository"
)

type UserService interface {
	Register(username, password string) (*domain.User, error)
	Authenticate(username, password string) (*domain.User, error)
}

type userService struct {
	users  repository.UserRepository
	crypto Crypto
}

func NewUserService(users repository.UserRepository, crypto Crypto) *userService {
	return &userService{users: users, crypto: crypto}
}

// Authenticate retrieves user by username and compaires password hashes
// Returns *domain.User if hashed input password corresponds stored in repository for user
// Otherwise returns nil and ErrInvalidCredentials
func (us *userService) Authenticate(username, password string) (*domain.User, error) {
	op := "authenticate"

	if strings.TrimSpace(username) == "" {
		return nil, ErrInvalidCredentials
	}

	if password == "" {
		return nil, ErrInvalidCredentials
	}

	if len(username) > 64 || len(password) > 256 {
		return nil, ErrInvalidCredentials
	}

	user, err := us.users.FindByUsername(username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		slog.Error("find user failed", "op", op, "err", err)
		return nil, ErrInternal
	}
	passwordHash := us.crypto.HashPassword(password, user.Salt)
	if len(passwordHash) != len(user.PasswordHash) || subtle.ConstantTimeCompare(passwordHash, user.PasswordHash) != 1 {
		return nil, ErrInvalidCredentials
	}
	return user, nil
}

// Register creates and stores new user
// Makes authentication salt and encryption key salt
// If username is taken return nil and ErrUsernameTaken
func (us *userService) Register(username, password string) (*domain.User, error) {
	op := "register"
	var user domain.User

	if strings.TrimSpace(username) == "" || len(username) > 32 {
		return nil, ErrInvalidUsername
	}

	if len(password) < 8 || len(password) > 256 {
		return nil, ErrInvalidPassword
	}

	salt, err := us.crypto.NewSalt(16)
	if err != nil {
		slog.Error("generating salt failed", "op", op, "err", err)
		return nil, ErrInternal
	}
	encSalt, err := us.crypto.NewSalt(16)
	if err != nil {
		slog.Error("generating salt failed", "op", op, "err", err)
		return nil, ErrInternal
	}

	user.Username = username
	user.Salt = salt
	user.EncSalt = encSalt
	user.PasswordHash = us.crypto.HashPassword(password, user.Salt)

	if user, err := us.users.Create(&user); err != nil {
		if errors.Is(err, repository.ErrAlreadyExists) {
			return nil, ErrUsernameTaken
		}
		slog.Error("create user failed", "op", op, "err", err)
		return nil, ErrInternal
	} else {
		return user, nil
	}
}
