package service

import "errors"

var (
	ErrInternal           = errors.New("internal error")
	ErrNotFound           = errors.New("not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidKey         = errors.New("invalid key")
	ErrInvalidUserID      = errors.New("invalid userID")
	ErrInvalidUsername    = errors.New("invalid username")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrUsernameTaken      = errors.New("username taken")
)
