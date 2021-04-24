package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var ErrInvalidJwt = errors.New("invalid jwt")

func parseJwt(tokenString string, secret []byte, c *Claims) error {
	_, err := jwt.ParseWithClaims(tokenString, c, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidJwt
		}
		return secret, nil
	})
	if err != nil {
		return fmt.Errorf("could not parse token: %w", err)
	}

	now := time.Now()
	fmt.Printf("%+v\n", c)
	deadline := time.Unix(c.ExpiresAt, 0).In(time.UTC)
	if deadline.Before(now) {
		return ErrUnauthorized
	}
	return nil
}

//buildJwt builds a JWT token with custom claims
func buildJwt(id, username, fullName string, secret []byte, validity time.Duration, scope Scope) (string, error) {
	ttl := time.Now().Add(validity)
	c := newClaims()
	defer returnClaims(c)
	c.Id = id
	c.Username = username
	c.Name = fullName
	c.Scope = scope
	c.ExpiresAt = ttl.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, *c)
	return token.SignedString(secret)
}
