package jwt

import (
	"net/http"

	"github.com/dmitrymomot/go-errors"
)

// Predefined JWT errors
var (
	ErrTokenRevoked            = errors.NewHTTP(http.StatusUnauthorized, "token is revoked")
	ErrTokenMalformed          = errors.NewHTTP(http.StatusUnauthorized, "malformed token")
	ErrTokenExpired            = errors.NewHTTP(http.StatusUnauthorized, "token is expired")
	ErrTokenNotValidYet        = errors.NewHTTP(http.StatusUnauthorized, "token is not active yet")
	ErrAuthTokenMissed         = errors.NewHTTP(http.StatusUnauthorized, "missed authorization token")
	ErrBlacklistNotSpecified   = errors.New("blacklist adapter is not specified")
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
	ErrCouldNotRefresh         = errors.NewHTTP(http.StatusUnauthorized, "could not refresh token, log in again")
)
