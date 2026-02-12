package secret

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type AddSecretRequest struct {
	Data json.RawMessage `json:"data"`
}

type AddSecretResponse struct {
	UUID      uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"createdAt"`
}

type SecretResponse struct {
	UUID      uuid.UUID       `json:"id"`
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"createdAt"`
}
