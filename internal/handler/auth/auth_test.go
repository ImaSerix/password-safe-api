package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/handler/auth"
	"github.com/ImaSerix/password-safe-api/internal/service"
	"github.com/google/uuid"
)

type fakeUserService struct {
	user *domain.User
	err  error
}

func (fus *fakeUserService) Register(username, password string) (*domain.User, error) {
	return nil, nil
}

func (fus *fakeUserService) Authenticate(username, password string) (*domain.User, error) {
	fus.user.Username = username
	fus.user.PasswordHash = []byte(password)
	if fus.err != nil {
		return nil, fus.err
	}
	return fus.user, nil
}

type fakeCrypto struct {
}

func (fc *fakeCrypto) Encrypt(key, plaintext []byte) (ciphertext []byte, nonce []byte, err error) {
	return nil, nil, nil
}
func (fc *fakeCrypto) Decrypt(key, ciphertext, nonce []byte) (plaintext []byte, err error) {
	return nil, nil
}
func (fc *fakeCrypto) DeriveKey(password string, salt []byte) []byte {
	return []byte("nice key")
}
func (fc *fakeCrypto) HashPassword(password string, salt []byte) []byte {
	return nil
}
func (fc *fakeCrypto) NewSalt(size int) ([]byte, error) {
	return nil, nil
}
func (fc *fakeCrypto) NewNonce(size int) ([]byte, error) {
	return nil, nil
}

func TestAuthMiddleware_Success(t *testing.T) {
	us := &fakeUserService{
		user: &domain.User{
			UUID: uuid.New(),
		},
	}
	c := &fakeCrypto{}
	called := false

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.Header.Set("X-Username", "username")
	req.Header.Set("X-Password", "password")

	rr := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		if user, _ := auth.User(r.Context()); user == nil {
			t.Fatal("user missing in context")
		}
	})

	mv := auth.AuthMiddleware(us, c)

	mv(next).ServeHTTP(rr, req)
	if !called {
		t.Fatal("next handler was not called")
	}
	if us.user.Username != "username" {
		t.Fatalf("expected username 'username', got %q", us.user.Username)
	}

	if string(us.user.PasswordHash) != "password" {
		t.Fatalf("expected password 'password', got %q", us.user.Username)
	}
}

func TestAuthMiddleware_NoUsername(t *testing.T) {
	us := &fakeUserService{
		user: &domain.User{
			UUID: uuid.New(),
		},
	}
	c := &fakeCrypto{}
	called := false

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.Header.Set("X-Password", "password")

	rr := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		if user, _ := auth.User(r.Context()); user == nil {
			t.Fatal("user missing in context")
		}
	})

	mv := auth.AuthMiddleware(us, c)

	mv(next).ServeHTTP(rr, req)
	if called {
		t.Fatal("next handler was called")
	}

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected code 401, got %q", rr.Code)
	}
}

func TestAuthMiddleware_InvalidCredentials(t *testing.T) {
	us := &fakeUserService{
		user: &domain.User{
			UUID: uuid.New(),
		},
		err: service.ErrInvalidCredentials,
	}
	c := &fakeCrypto{}
	called := false

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.Header.Set("X-Username", "username")
	req.Header.Set("X-Password", "password")

	rr := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		if user, _ := auth.User(r.Context()); user == nil {
			t.Fatal("user missing in context")
		}
	})

	mv := auth.AuthMiddleware(us, c)

	mv(next).ServeHTTP(rr, req)
	if called {
		t.Fatal("next handler was called")
	}

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected code 401, got %q", rr.Code)
	}
}

func TestAuthMiddleware_InternalError(t *testing.T) {
	us := &fakeUserService{
		user: &domain.User{
			UUID: uuid.New(),
		},
		err: service.ErrInternal,
	}
	c := &fakeCrypto{}
	called := false

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	req.Header.Set("X-Username", "username")
	req.Header.Set("X-Password", "password")

	rr := httptest.NewRecorder()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true

		if user, _ := auth.User(r.Context()); user == nil {
			t.Fatal("user missing in context")
		}
	})

	mv := auth.AuthMiddleware(us, c)

	mv(next).ServeHTTP(rr, req)
	if called {
		t.Fatal("next handler was called")
	}

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected code 500, got %q", rr.Code)
	}
}
