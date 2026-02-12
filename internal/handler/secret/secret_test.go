package secret_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ImaSerix/password-safe-api/internal/domain"
	"github.com/ImaSerix/password-safe-api/internal/handler/auth"
	"github.com/ImaSerix/password-safe-api/internal/handler/secret"
	"github.com/ImaSerix/password-safe-api/internal/service"
	"github.com/google/uuid"
)

type fakeSecretService struct {
	secret       *domain.Secret
	keyGot       []byte
	userIdGot    uuid.UUID
	plaintextGot []byte
	err          error
}

func (fss *fakeSecretService) Add(userID uuid.UUID, key []byte, plaintext []byte) (*domain.Secret, error) {
	if fss.err != nil {
		return nil, fss.err
	}

	fss.keyGot = key
	fss.plaintextGot = plaintext
	fss.secret = &domain.Secret{
		UUID:          uuid.New(),
		UserID:        userID,
		EncryptedData: []byte("encrypted data"),
		Nonce:         []byte("nonce"),
	}
	return fss.secret, nil
}
func (fss *fakeSecretService) GetByUser(userID uuid.UUID, key []byte) ([]*domain.DecryptedSecret, error) {
	if fss.err != nil {
		return nil, fss.err
	}
	fss.userIdGot = userID
	fss.keyGot = key
	return []*domain.DecryptedSecret{
		{UUID: uuid.New(), Data: []byte(`"plain text"`)},
	}, nil
}

func TestSecretHandler_Add_Success(t *testing.T) {
	ss := &fakeSecretService{}
	sh := secret.NewSecretHandler(ss)

	user := &domain.User{
		UUID:         uuid.New(),
		Username:     "username",
		PasswordHash: []byte("passwordHash"),
		Salt:         []byte("salt"),
		EncSalt:      []byte("encSalt"),
	}

	body := `{"data":"nice data"}`
	req := httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(body))
	ctx := auth.WithUser(req.Context(), user)
	ctx = auth.WithCryptoKey(ctx, []byte("crypto key"))
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()

	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sh.Add(w, r)
	}).ServeHTTP(rr, req)

	var res secret.SecretResponse

	err := json.NewDecoder(rr.Result().Body).Decode(&res)
	if err != nil {
		t.Fatal("expected response in format secret.SecretResponse")
	}
	if res.UUID == uuid.Nil {
		t.Fatal("expected UUID in response")
	}
	if user.UUID != ss.secret.UserID {
		t.Fatalf("expected UUID %q, got %q", user.UUID, ss.secret.UUID)
	}
	if !bytes.Equal(ss.keyGot, []byte("crypto key")) {
		t.Fatalf("expected key %q, got %q", []byte("crypto key"), ss.keyGot)
	}
	if !bytes.Equal(ss.plaintextGot, []byte(`"nice data"`)) {
		t.Fatalf("expected plaintext %q, got %q", []byte(`"nice data"`), ss.plaintextGot)
	}
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected code 201, got %v", rr.Code)
	}
}

func TestSecretHandler_Add_NoUserInContext(t *testing.T) {
	ss := &fakeSecretService{}
	sh := secret.NewSecretHandler(ss)

	body := `{"data":"nice data"}`
	req := httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(body))
	rr := httptest.NewRecorder()

	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sh.Add(w, r)
	}).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected code 500, got %v", rr.Code)
	}
}

func TestSecretHandler_Add_NoKeyInContext(t *testing.T) {
	ss := &fakeSecretService{}
	sh := secret.NewSecretHandler(ss)

	user := &domain.User{
		UUID:         uuid.New(),
		Username:     "username",
		PasswordHash: []byte("passwordHash"),
		Salt:         []byte("salt"),
		EncSalt:      []byte("encSalt"),
	}

	body := `{"data":"nice data"}`
	req := httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(body))
	rr := httptest.NewRecorder()

	ctx := auth.WithUser(req.Context(), user)
	req = req.WithContext(ctx)

	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sh.Add(w, r)
	}).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected code 500, got %v", rr.Code)
	}
}

func TestSecretHandler_Add_InvalidJSON(t *testing.T) {
	ss := &fakeSecretService{}
	sh := secret.NewSecretHandler(ss)

	user := &domain.User{
		UUID:         uuid.New(),
		Username:     "username",
		PasswordHash: []byte("passwordHash"),
		Salt:         []byte("salt"),
		EncSalt:      []byte("encSalt"),
	}

	body := `{nice data}`
	req := httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(body))
	rr := httptest.NewRecorder()

	ctx := auth.WithUser(req.Context(), user)
	ctx = auth.WithCryptoKey(ctx, []byte("crypto key"))
	req = req.WithContext(ctx)

	http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sh.Add(w, r)
	}).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected code 400, got %v", rr.Code)
	}
}

func TestSecretHandler_GetAll_Success(t *testing.T) {
	ss := &fakeSecretService{}
	sh := secret.NewSecretHandler(ss)

	user := &domain.User{
		UUID:         uuid.New(),
		Username:     "username",
		PasswordHash: []byte("passwordHash"),
		Salt:         []byte("salt"),
		EncSalt:      []byte("encSalt"),
	}

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	rr := httptest.NewRecorder()

	ctx := auth.WithUser(req.Context(), user)
	ctx = auth.WithCryptoKey(ctx, []byte("crypto key"))
	req = req.WithContext(ctx)

	sh.GetAll(rr, req)

	var res []secret.SecretResponse

	err := json.NewDecoder(rr.Result().Body).Decode(&res)
	if err != nil {
		t.Fatal("expected response in format secret.SecretResponse")
	}
	if len(res) == 0 {
		t.Fatal("expected response having 1 element")
	}
	if ss.userIdGot != user.UUID {
		t.Fatalf("expected service getting %v user id, got %v", user.UUID, ss.userIdGot)
	}
	if !bytes.Equal(ss.keyGot, []byte("crypto key")) {
		t.Fatalf("expected service getting %q key, got %q", []byte("crypto key"), ss.keyGot)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected code 200, got %v", rr.Code)
	}
}

func TestSecretHandler_GetAll_NoUserInContext(t *testing.T) {
	ss := &fakeSecretService{}
	sh := secret.NewSecretHandler(ss)

	req := httptest.NewRequest(http.MethodGet, "/secrets", nil)
	rr := httptest.NewRecorder()

	sh.GetAll(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected code 500, got %v", rr.Code)
	}
}

func TestSecretHandler_GetAll_NoKeyInContext(t *testing.T) {
	ss := &fakeSecretService{}
	sh := secret.NewSecretHandler(ss)

	user := &domain.User{
		UUID:         uuid.New(),
		Username:     "username",
		PasswordHash: []byte("passwordHash"),
		Salt:         []byte("salt"),
		EncSalt:      []byte("encSalt"),
	}

	body := `{"data":"nice data"}`
	req := httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(body))
	rr := httptest.NewRecorder()

	ctx := auth.WithUser(req.Context(), user)
	req = req.WithContext(ctx)

	sh.GetAll(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected code 500, got %v", rr.Code)
	}
}

func TestSecretHandler_GetAll_NotFound(t *testing.T) {
	ss := &fakeSecretService{
		err: service.ErrNotFound,
	}
	sh := secret.NewSecretHandler(ss)

	user := &domain.User{
		UUID:         uuid.New(),
		Username:     "username",
		PasswordHash: []byte("passwordHash"),
		Salt:         []byte("salt"),
		EncSalt:      []byte("encSalt"),
	}

	body := `{"data":"nice data"}`
	req := httptest.NewRequest(http.MethodPost, "/secrets", strings.NewReader(body))
	rr := httptest.NewRecorder()

	ctx := auth.WithUser(req.Context(), user)
	ctx = auth.WithCryptoKey(ctx, []byte("crypto key"))
	req = req.WithContext(ctx)

	sh.GetAll(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected code 404, got %v", rr.Code)
	}
}
