package handler

import (
	"errors"
	"net/http"

	"github.com/ImaSerix/password-safe-api/internal/service"
)

func WriteServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidUsername),
		errors.Is(err, service.ErrInvalidPassword),
		errors.Is(err, service.ErrInvalidCredentials):
		http.Error(w, err.Error(), http.StatusBadRequest)

	case errors.Is(err, service.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)

	case errors.Is(err, service.ErrUsernameTaken):
		http.Error(w, "username taken", http.StatusConflict)

	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
