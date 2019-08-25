package jwt

import "github.com/dgrijalva/jwt-go"

type (
	// Claims interface
	Claims interface {
		jwt.Claims
	}

	// DefaultClaims struct
	DefaultClaims struct {
		UserID        string `json:"uid,omitempty"`
		ApplicationID string `json:"aid,omitempty"`
		jwt.StandardClaims
	}
)
