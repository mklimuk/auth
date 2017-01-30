package user

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mklimuk/goerr"
	"golang.org/x/crypto/bcrypt"
)

var secret = []byte("Sample123")

type claims struct {
	jwt.StandardClaims
	Username    string `json:"username"`
	Name        string `json:"name"`
	Permissions int    `json:"permissions"`
}

//Manager is an access layer for user-related operations
type Manager interface {
	Login(username, password string) (string, error)
	Create(u *User) (*User, error)
	CheckToken(token string, update bool) (string, error)
}

type man struct {
	users []*User
}

//NewManager is a user manager constructor
func NewManager(users []*User) Manager {
	m := man{users}
	return Manager(&m)
}

func (m *man) Login(username, password string) (token string, err error) {
	for _, u := range m.users {
		if u.Username == username {
			if err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)); err != nil {
				return token, goerr.NewError("Invalid password", goerr.Unauthorized)
			}
			return BuildToken(username, u.Name, u.Rigths)
		}
	}
	return token, goerr.NewError("User not found", goerr.NotFound)
}

func (m *man) CheckToken(token string, update bool) (string, error) {
	var c *claims
	var err error
	if c, err = parseToken(token); err != nil {
		return token, err
	}
	if update {
		var updated string
		if updated, err = BuildToken(c.Username, c.Name, c.Permissions); err == nil {
			return updated, err
		}
	}
	return token, err
}

func (m *man) Create(u *User) (*User, error) {
	var err error
	var pwd []byte
	if pwd, err = bcrypt.GenerateFromPassword([]byte(u.Password), 10); err != nil {
		return nil, err
	}
	u.Password = string(pwd)
	//saves it in memory
	m.users = append(m.users, u)
	return u, nil
}

func parseToken(tokenString string) (res *claims, err error) {
	var ok bool
	var token *jwt.Token
	res = new(claims)
	if token, err = jwt.ParseWithClaims(tokenString, res, func(token *jwt.Token) (interface{}, error) {
		if _, ok = token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, goerr.NewError(fmt.Sprintf("Unexpected signing method: %v", token.Header["alg"]), goerr.BadRequest)
		}
		return secret, nil
	}); err != nil {
		return res, err
	}

	if res, ok = token.Claims.(*claims); !ok {
		err = goerr.NewError("Could not parse token", goerr.BadRequest)
	}
	return res, err

}

//BuildToken builds a JWT token with custom claims
func BuildToken(username, fullName string, rights int) (string, error) {
	ttl := time.Now().Add(time.Duration(30) * time.Minute)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		Username:    username,
		Name:        fullName,
		Permissions: rights,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: ttl.Unix(),
		},
	})
	return token.SignedString(secret)
}
