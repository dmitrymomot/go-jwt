package jwt

import "github.com/dgrijalva/jwt-go"

type (
	// Claims interface
	Claims interface {
		jwt.Claims
		ID() string
	}

	// DefaultClaims struct
	DefaultClaims struct {
		UserID        string `json:"uid,omitempty"`
		ApplicationID string `json:"aid,omitempty"`
		Role          string `json:"rol,omitempty"`
		jwt.StandardClaims
	}
)

// ID getter function
func (c DefaultClaims) ID() string {
	return c.Id
}
