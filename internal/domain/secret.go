package domain

import (
	"time"

	"github.com/google/uuid"
)

type Secret struct {
	UUID          uuid.UUID
	UserID        uuid.UUID
	EncryptedData []byte
	Nonce         []byte
	CreatedAt     time.Time
}
