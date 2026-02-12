package repository

import (
	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/google/uuid"
)

type UserRepository interface {
	Create(u *domain.User) (*domain.User, error)
	FindByID(id uuid.UUID) (*domain.User, error)
	FindByUsername(username string) (*domain.User, error)
}
