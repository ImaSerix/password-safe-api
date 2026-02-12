package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ImaSerix/password-safe-api/internal/service"
)

// AuthMiddleware authenticates user.
// Extracts credentials from header.
// Adds user and crypto key in request context.
func AuthMiddleware(us service.UserService, crypto service.Crypto) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			username := r.Header.Get("X-Username")
			password := r.Header.Get("X-Password")

			if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
				http.Error(w, "missing credentials", http.StatusUnauthorized)
				return
			}

			user, err := us.Authenticate(username, password)

			if err != nil {
				if errors.Is(err, service.ErrInvalidCredentials) {
					http.Error(w, "invalid credentials", http.StatusUnauthorized)
					return
				}

				slog.Error("auth failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			cryptokey := crypto.DeriveKey(password, user.EncSalt)

			ctx := WithUser(r.Context(), user)
			ctx = WithCryptoKey(ctx, cryptokey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
