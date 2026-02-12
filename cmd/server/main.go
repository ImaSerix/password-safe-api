package main

import (
	"log"
	"net/http"

	"github.com/ImaSerix/password-safe-api/internal/config"
	"github.com/ImaSerix/password-safe-api/internal/crypto"
	"github.com/ImaSerix/password-safe-api/internal/handler/auth"
	"github.com/ImaSerix/password-safe-api/internal/handler/secret"
	"github.com/ImaSerix/password-safe-api/internal/handler/user"
	"github.com/ImaSerix/password-safe-api/internal/repository/postgres"
	"github.com/ImaSerix/password-safe-api/internal/service"
	"github.com/ImaSerix/password-safe-api/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Erorr while loading .env file: %v", err)
	}

	cfg := config.Load()

	db, err := storage.NewDBConnection(cfg.DB.FormatDSN())
	if err != nil {
		log.Fatalf("error while connecting to DB: %v", err)
	}

	crypt := crypto.New()
	userService := service.NewUserService(postgres.NewUserRepository(db), crypt)
	secretService := service.NewSecretService(postgres.NewSecretRepository(db), crypt)

	userHandler := user.NewUserHandler(userService)
	secretHandler := secret.NewSecretHandler(secretService)

	r := chi.NewRouter()

	r.Post("/register", userHandler.Register)

	r.Route("/secrets", func(r chi.Router) {
		r.Use(auth.AuthMiddleware(userService, crypt))

		r.Post("/", secretHandler.Add)
		r.Get("/", secretHandler.GetAll)
	})

	log.Fatal(http.ListenAndServe(":8080", r))
}
