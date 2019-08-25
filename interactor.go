package jwt

import (
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dmitrymomot/go-jwt/blacklist"
	"github.com/dmitrymomot/go-utilities/uuid"
)

type (
	// Interactor interface
	Interactor interface {
		New(uid, aid string) (string, error)
		NewWithClaims(Claims) (string, error)
		Parse(token string, claims interface{}) error
		ParseFromRequest(r *http.Request, claims interface{}) error
		GetTokenStringFromRequest(r *http.Request) (string, error)
		Revoke(tokenID string) error
		IsRevoked(tokenID string) bool
		RefreshToken(claims interface{}) (string, error)
		RefreshTokenFromString(tokenString string) (string, error)
	}

	interactor struct {
		signingKey []byte
		ttl        int64
		bl         blacklist.Blacklist
	}
)

// NewInteractor factory
func NewInteractor(signingKey string, ttl int64, bl blacklist.Blacklist) (Interactor, error) {
	if bl == nil {
		return nil, ErrBlacklistNotSpecified
	}
	return &interactor{[]byte(signingKey), ttl, bl}, nil
}

func (i *interactor) New(uid, aid string) (string, error) {
	claims := DefaultClaims{
		uid, aid,
		jwt.StandardClaims{
			Id:        uuid.New().String(),
			ExpiresAt: time.Now().Add(time.Duration(i.ttl) * time.Second).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(i.signingKey)
}

func (i *interactor) NewWithClaims(cl Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cl)
	return token.SignedString(i.signingKey)
}

func (i *interactor) Parse(token string, claims interface{}) error {
	return nil
}

func (i *interactor) ParseFromRequest(r *http.Request, claims interface{}) error {
	tokenString, err := i.GetTokenStringFromRequest(r)
	if err != nil {
		return err
	}
	return i.Parse(tokenString, claims)
}

func (i *interactor) GetTokenStringFromRequest(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrAuthTokenMissed
	}
	if !strings.HasPrefix(authHeader, "Bearer") {
		return "", ErrTokenMalformed
	}
	tokenString := strings.Trim(strings.TrimPrefix(authHeader, "Bearer"), " ")
	return tokenString, nil
}

func (i *interactor) Revoke(tokenID string) error {
	return i.bl.Add(tokenID)
}

func (i *interactor) IsRevoked(tokenID string) bool {
	return i.bl.Exists(tokenID)
}

func (i *interactor) RefreshToken(claims interface{}) (string, error) {
	var cl Claims
	if cl, ok := claims.(DefaultClaims); ok {
		cl.Id = uuid.New().String()
		cl.ExpiresAt = time.Now().Add(time.Duration(i.ttl) * time.Second).Unix()
		cl.IssuedAt = time.Now().Unix()
	} else if cl, ok := claims.(jwt.StandardClaims); ok {
		cl.Id = uuid.New().String()
		cl.ExpiresAt = time.Now().Add(time.Duration(i.ttl) * time.Second).Unix()
		cl.IssuedAt = time.Now().Unix()
	}

	return i.NewWithClaims(cl)
}

func (i *interactor) RefreshTokenFromString(tokenString string) (string, error) {
	cl := new(DefaultClaims)
	if err := i.Parse(tokenString, cl); err != nil {
		return "", err
	}
	return i.NewWithClaims(cl)
}
