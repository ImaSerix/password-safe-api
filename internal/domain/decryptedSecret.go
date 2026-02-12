package domain

import (
	"time"

	"github.com/google/uuid"
)

type DecryptedSecret struct {
	UUID      uuid.UUID
	Data      []byte
	CreatedAt time.Time
}
