package auth

import (
	"sync"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"

	"github.com/oklog/ulid"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

var userPool *sync.Pool

func init() {
	userPool = &sync.Pool{
		New: func() interface{} {
			return &User{}
		},
	}
}

func newUser() *User {
	return userPool.New().(*User)
}

func returnUser(u *User) {
	*u = User{}
	userPool.Put(u)
}

//User contains user properties
type User struct {
	ID       string `json:"id" yaml:"id,omitempty" storm:"unique"`
	Username string `json:"username" yaml:"username" storm:"unique"`
	Name     string `json:"name" yaml:"name"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	Scope    Scope  `json:"scope" yaml:"scope"`
}

func (u User) Validate() error {
	return validation.ValidateStruct(&u,
		validation.Field(&u.Password, validation.Required, validation.Length(6, 0)))
}

func (u User) toJwt(secret []byte, scope Scope, ttl time.Duration) (string, error) {
	return buildJwt(u.ID, u.Username, u.Name, secret, ttl, scope)
}

func LoadUsersFromFile(file string, fs afero.Fs) ([]*User, error) {
	data, err := afero.ReadFile(fs, file)
	if err != nil {
		return nil, err
	}
	var users []*User
	err = yaml.Unmarshal(data, &users)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.ID != "" {
			continue
		}
		ID, err := ulid.New(ulid.Timestamp(time.Now()), entropy)
		if err != nil {
			continue
		}
		u.ID = ID.String()
	}
	return users, nil
}
