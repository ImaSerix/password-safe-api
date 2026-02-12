package user

import (
	"encoding/json"
	"net/http"

	"github.com/ImaSerix/password-safe-api/internal/handler"
	"github.com/ImaSerix/password-safe-api/internal/service"
)

type UserHandler struct {
	users service.UserService
}

func NewUserHandler(users service.UserService) *UserHandler {
	return &UserHandler{users: users}
}

// Register creates and stores new user.
// Parses request body for username and password.
func (uh *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	user, err := uh.users.Register(req.Username, req.Password)
	if err != nil {
		handler.WriteServiceError(w, err)
		return
	}

	resp := RegisterResponse{
		UUID:      user.UUID,
		CreatedAt: user.CreatedAt,
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}
