package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	UUID         uuid.UUID
	Username     string
	PasswordHash []byte
	Salt         []byte
	EncSalt      []byte
	CreatedAt    time.Time
}
