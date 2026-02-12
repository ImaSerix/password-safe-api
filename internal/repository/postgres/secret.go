package postgres

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/google/uuid"
)

type SecretRepository struct {
	db *sql.DB
}

func NewSecretRepository(db *sql.DB) *SecretRepository {
	return &SecretRepository{
		db: db,
	}
}

func (sr *SecretRepository) Create(s *domain.Secret) (*domain.Secret, error) {
	var id uuid.UUID
	var createdAt time.Time

	err := sr.db.QueryRow("INSERT INTO secrets (user_id, encrypted_data, nonce) VALUES ($1, $2, $3) RETURNING id, created_at", s.UserID, s.EncryptedData, s.Nonce).Scan(&id, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("insert secret: %w", err)
	}

	s.UUID = id
	s.CreatedAt = createdAt
	return s, nil
}

func (sr *SecretRepository) FindByID(id uuid.UUID) (*domain.Secret, error) {
	var secret domain.Secret
	row := sr.db.QueryRow("SELECT id, user_id, encrypted_data, nonce, created_at FROM secrets WHERE id = $1", id)

	if err := row.Scan(&secret.UUID, &secret.UserID, &secret.EncryptedData, &secret.Nonce, &secret.CreatedAt); err != nil {
		return nil, fmt.Errorf("finding secret: %w", err)
	}
	return &secret, nil
}

func (sr *SecretRepository) FindByUserID(userID uuid.UUID) ([]*domain.Secret, error) {
	var secrets []*domain.Secret
	rows, err := sr.db.Query("SELECT id, user_id, encrypted_data, nonce, created_at FROM secrets WHERE user_id = $1", userID)
	if err != nil {
		return nil, fmt.Errorf("finding secrets by userID: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var secret domain.Secret
		if err := rows.Scan(&secret.UUID, &secret.UserID, &secret.EncryptedData, &secret.Nonce, &secret.CreatedAt); err != nil {
			return nil, fmt.Errorf("finding secrets by userID: %w", err)
		}
		secrets = append(secrets, &secret)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("finding secrets by userID: %w", err)
	}
	return secrets, nil
}
