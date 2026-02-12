package user_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/handler/user"
	"github.com/google/uuid"
)

type fakeUserService struct {
	usernameGot string
	passwordGot string
	err         error
}

func (fus *fakeUserService) Authenticate(username, password string) (*domain.User, error) {
	return nil, nil
}

func (fus *fakeUserService) Register(username, password string) (*domain.User, error) {
	if fus.err != nil {
		return nil, fus.err
	}
	fus.usernameGot = username
	fus.passwordGot = password
	return &domain.User{
		UUID:     uuid.New(),
		Username: username,
	}, nil
}

func TestUserHandler_Register_Success(t *testing.T) {
	fus := &fakeUserService{}
	us := user.NewUserHandler(fus)

	body := `{"username": "usrName", "password": "password"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	rr := httptest.NewRecorder()

	us.Register(rr, req)

	var res user.RegisterResponse

	err := json.NewDecoder(rr.Result().Body).Decode(&res)
	if err != nil {
		t.Fatal("expected response in format user.RegisterResponse")
	}
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected code 201, got %v", rr.Code)
	}
	if fus.usernameGot != "usrName" {
		t.Fatalf("expected username 'usrName', got %v", fus.usernameGot)
	}
	if fus.passwordGot != "password" {
		t.Fatalf("expected password 'password', got %v", fus.passwordGot)
	}
}

func TestUserHandler_Register_InvalidJson(t *testing.T) {
	fus := &fakeUserService{}
	us := user.NewUserHandler(fus)

	body := `invalid JSON`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	rr := httptest.NewRecorder()

	us.Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected code 400, got %v", rr.Code)
	}
}
