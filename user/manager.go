package user

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mklimuk/goerr"
	"golang.org/x/crypto/bcrypt"
)

var secret = []byte("Sample123")

//Manager is an access layer for user-related operations
type Manager interface {
	Login(username, password string) (string, error)
	Create(u *User) (*User, error)
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
			return buildToken(username, u.Name, u.Rigths)
		}
	}
	return token, goerr.NewError("User not found", goerr.NotFound)
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

func buildToken(username, fullName string, rights int) (string, error) {
	ttl := time.Now().Add(time.Duration(30) * time.Minute)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"name":     fullName,
		"exp":      ttl.Unix(),
	})
	return token.SignedString(secret)
}
