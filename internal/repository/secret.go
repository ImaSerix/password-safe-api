package repository

import (
	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/google/uuid"
)

type SecretRepository interface {
	Create(u *domain.Secret) (*domain.Secret, error)
	FindByID(id uuid.UUID) (*domain.Secret, error)
	FindByUserID(userID uuid.UUID) ([]*domain.Secret, error)
}
