package auth

import (
	"context"

	"github.com/ImaSerix/password-safe-api/internal/domain"
)

type userKeyType struct{}
type cryptoKeyType struct{}

var (
	userKey   = userKeyType{}
	cryptoKey = cryptoKeyType{}
)

func WithUser(ctx context.Context, user *domain.User) context.Context {
	return context.WithValue(ctx, userKey, user)
}

func User(ctx context.Context) (*domain.User, bool) {
	value, ok := ctx.Value(userKey).(*domain.User)
	return value, ok
}

func WithCryptoKey(ctx context.Context, key []byte) context.Context {
	return context.WithValue(ctx, cryptoKey, key)
}

func CryptoKey(ctx context.Context) ([]byte, bool) {
	value, ok := ctx.Value(cryptoKey).([]byte)
	return value, ok
}
