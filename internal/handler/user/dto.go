package user

import (
	"time"

	"github.com/google/uuid"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	UUID      uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
}
