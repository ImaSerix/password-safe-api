package secret

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ImaSerix/password-safe-api/internal/handler"
	"github.com/ImaSerix/password-safe-api/internal/handler/auth"
	"github.com/ImaSerix/password-safe-api/internal/service"
)

type SecretHandler struct {
	secrets service.SecretService
}

func NewSecretHandler(secrets service.SecretService) *SecretHandler {
	return &SecretHandler{
		secrets: secrets,
	}
}

// Add creates and stores secret.
// Parses request body for data.
func (sh *SecretHandler) Add(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.User(r.Context())
	if !ok {
		slog.Error("reading user from context failed")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	key, ok := auth.CryptoKey(r.Context())
	if !ok {
		slog.Error("reading key from context failed")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var req AddSecretRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	secret, err := sh.secrets.Add(user.UUID, key, req.Data)
	if err != nil {
		handler.WriteServiceError(w, err)
		return
	}

	resp := AddSecretResponse{
		UUID:      secret.UUID,
		CreatedAt: secret.CreatedAt,
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// GetAll retrieves secrets by user.
// Writes in request body decrypted secrets.
func (sh *SecretHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.User(r.Context())
	if !ok {
		slog.Error("reading user from context failed")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	key, ok := auth.CryptoKey(r.Context())
	if !ok {
		slog.Error("reading key from context failed")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	secrets, err := sh.secrets.GetByUser(user.UUID, key)
	if err != nil {
		handler.WriteServiceError(w, err)
		return
	}

	var resp []SecretResponse

	for _, secret := range secrets {
		resp = append(resp, SecretResponse{
			UUID:      secret.UUID,
			Data:      json.RawMessage(secret.Data),
			CreatedAt: secret.CreatedAt,
		})
	}

	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(resp)
}
