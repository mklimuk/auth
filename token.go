package auth

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"
)

var tokenPool *sync.Pool

func init() {
	tokenPool = &sync.Pool{
		New: func() interface{} {
			return &Token{}
		},
	}
	buf := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %v", err))
	}
}

func newToken() *Token {
	return tokenPool.New().(*Token)
}

func releaseToken(t *Token) {
	*t = Token{}
	userPool.Put(t)
}

type Token struct {
	Token     string `storm:"id"`
	Owner     string
	Created   time.Time
	ExpiresAt time.Time
	Scope     Scope
}

func generateToken(owner string, scope Scope, expires time.Time, size int) (Token, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ret := make([]byte, size)
	for i := 0; i < size; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return Token{}, fmt.Errorf("could not generate token: %w", err)
		}
		ret[i] = letters[num.Int64()]
	}
	return Token{
		Token:     string(ret),
		Owner:     owner,
		Created:   time.Now().In(time.UTC),
		Scope:     scope,
		ExpiresAt: expires,
	}, nil
}
