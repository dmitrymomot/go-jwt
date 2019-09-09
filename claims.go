package jwt

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dmitrymomot/go-utilities/uuid"
)

type (
	// Claims interface
	Claims interface {
		jwt.Claims
		ID() string
		ExpAt() int64
		Refresh(ttl int64) Claims
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

// ExpAt getter function returns expiration time in seconds
func (c DefaultClaims) ExpAt() int64 {
	return c.ExpiresAt
}

// Refresh claims
func (c DefaultClaims) Refresh(ttl int64) Claims {
	c.Id = uuid.New().String()
	c.ExpiresAt = time.Now().Add(time.Duration(ttl) * time.Second).Unix()
	c.IssuedAt = time.Now().Unix()
	return c
}
