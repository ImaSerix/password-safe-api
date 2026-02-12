package postgres

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

func (ur *UserRepository) Create(u *domain.User) (*domain.User, error) {
	var id uuid.UUID
	var createAt time.Time
	err := ur.db.QueryRow("INSERT INTO users (username, password_hash, salt, enc_salt) VALUES ($1, $2, $3, $4) RETURNING id, created_at", u.Username, u.PasswordHash, u.Salt, u.EncSalt).Scan(&id, &createAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				return nil, repository.ErrAlreadyExists
			}
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}

	u.UUID = id
	u.CreatedAt = createAt
	return u, nil
}

func (ur *UserRepository) FindByID(id uuid.UUID) (*domain.User, error) {
	var user domain.User
	row := ur.db.QueryRow("SELECT id, username, password_hash, salt, enc_salt, created_at FROM users WHERE id = $1", id)

	if err := row.Scan(&user.UUID, &user.Username, &user.PasswordHash, &user.Salt, &user.EncSalt, &user.CreatedAt); err != nil {
		return nil, fmt.Errorf("finding user: %w", err)
	}
	return &user, nil
}

func (ur *UserRepository) FindByUsername(username string) (*domain.User, error) {
	var user domain.User
	row := ur.db.QueryRow("SELECT id, username, password_hash, salt, enc_salt, created_at FROM users WHERE username = $1", username)

	if err := row.Scan(&user.UUID, &user.Username, &user.PasswordHash, &user.Salt, &user.EncSalt, &user.CreatedAt); err != nil {
		return nil, fmt.Errorf("find user by username: %w", err)
	}
	return &user, nil
}
