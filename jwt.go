package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidJwt = errors.New("invalid jwt")

func parseJwt(tokenString string, secret []byte, c *Claims) error {
	t, err := jwt.ParseWithClaims(tokenString, c, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidJwt
		}
		return secret, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenMalformed):
			return fmt.Errorf("malformed token: %w", ErrInvalidJwt)
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return fmt.Errorf("invalid signature: %w", ErrInvalidJwt)
		case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
			return fmt.Errorf("token expired or not valid yet: %w", ErrInvalidJwt)
		default:
			return fmt.Errorf("could not parse token: %w", ErrInvalidJwt)
		}
	}
	if !t.Valid {
		return fmt.Errorf("invalid token: %w", ErrInvalidJwt)
	}
	if c.Scope > 7 {
		return fmt.Errorf("invalid scope: %w", ErrInvalidJwt)
	}
	if c.Id == "" || c.Username == "" || c.Name == "" {
		return fmt.Errorf("missing claims: %w", ErrInvalidJwt)
	}
	return nil
}

// buildJwt builds a JWT token with custom claims
func buildJwt(id, username, fullName string, secret []byte, validity time.Duration, scope Scope) (string, error) {
	ttl := time.Now().Add(validity)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		Id:       id,
		Username: username,
		Name:     fullName,
		Scope:    scope,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(ttl),
		},
	})
	return token.SignedString(secret)
}
