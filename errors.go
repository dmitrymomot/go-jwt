package jwt

import (
	"net/http"

	"github.com/dmitrymomot/go-errors"
)

// Predefined JWT errors
var (
	ErrTokenRevoked          = errors.NewHTTP(http.StatusUnauthorized, "token is revoked")
	ErrTokenMalformed        = errors.NewHTTP(http.StatusUnauthorized, "malformed token")
	ErrTokenExpired          = errors.NewHTTP(http.StatusUnauthorized, "token is either expired or not active yet")
	ErrAuthTokenMissed       = errors.NewHTTP(http.StatusUnauthorized, "missed authorization token")
	ErrBlacklistNotSpecified = errors.New("blacklist adapter is not specified")
)
