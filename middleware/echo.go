package middleware

import (
	"github.com/dmitrymomot/go-errors"
	"github.com/dmitrymomot/go-jwt"
	"github.com/labstack/echo/v4"
)

// JWTEcho Middleware to use with echo.labstack framework
func JWTEcho(ji jwt.Interactor) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims := new(jwt.DefaultClaims)
			if err := ji.ParseFromRequest(c.Request(), claims); err != nil {
				return errors.New(err)
			}
			c.Set(JWTContextKey.String(), claims)
			return next(c)
		}
	}
}
