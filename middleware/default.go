package middleware

import (
	"context"
	"net/http"

	"github.com/dmitrymomot/go-errors"
	"github.com/dmitrymomot/go-jwt"
	"github.com/dmitrymomot/go-response"
)

// JWT Middleware
func JWT(ji jwt.Interactor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := new(jwt.DefaultClaims)
			if err := ji.ParseFromRequest(r, claims); err != nil {
				response.JSONErr(w, errors.New(err))
				return
			}
			ctx := context.WithValue(r.Context(), JWTContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
