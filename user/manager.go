package user

import (
	"fmt"
	"math/rand"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/oklog/ulid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/crypto/bcrypt"
	yaml "gopkg.in/yaml.v2"
)

var secret = []byte("Sample123")

var entropy *rand.Rand

func init() {
	t := time.Unix(1000000, 0)
	entropy = rand.New(rand.NewSource(t.UnixNano()))
}

var (
	ErrUnauthorized  = fmt.Errorf("unauthorized")
	ErrNotFound      = fmt.Errorf("user not found")
	ErrExists        = fmt.Errorf("user exists")
	ErrBadRequest    = fmt.Errorf("bad request")
	ErrWrongUserPass = fmt.Errorf("wrong username or password")
)

//Claims contains specific claims used in the auth system
type Claims struct {
	jwt.StandardClaims
	Username    string `json:"username"`
	Name        string `json:"name"`
	Permissions int    `json:"permissions"`
}

//Manager is an access layer for user-related operations
type Manager interface {
	Login(username, password string) (string, error)
	Create(u *User) (*User, error)
	Get(ID string) (*User, error)
	GetAll() ([]*User, error)
	CheckToken(token string, update bool) (string, *Claims, error)
}

type DefaultManager struct {
	store Store
}

//NewDefaultManager returns a default user manager
func NewDefaultManager(store Store) *DefaultManager {
	m := &DefaultManager{store: store}
	return m
}

func (m *DefaultManager) Login(username, password string) (string, error) {
	log.Infof("signin request from user %s", username)
	u, err := m.store.ByUsername(username)
	if err != nil {
		return "", err
	}
	if u == nil {
		log.Infof("user %s not found in store", username)
		return "", ErrNotFound
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		log.Infof("unsuccessful login for %s", username)
		return "", ErrWrongUserPass
	}
	return BuildToken(username, u.Name, u.Rigths)
}

func (m *DefaultManager) CheckToken(token string, update bool) (string, *Claims, error) {
	var c *Claims
	var err error
	if c, err = parseToken(token); err != nil {
		return token, c, err
	}
	if update {
		var updated string
		if updated, err = BuildToken(c.Username, c.Name, c.Permissions); err == nil {
			return updated, c, err
		}
	}
	return token, c, err
}

func (m *DefaultManager) Create(u *User) (*User, error) {
	ID, err := ulid.New(ulid.Timestamp(time.Now()), entropy)
	if err != nil {
		return nil, err
	}
	u.ID = ID.String()
	pwd, err := bcrypt.GenerateFromPassword([]byte(u.Password), 10)
	if err != nil {
		return nil, err
	}
	u.Password = string(pwd)
	err = m.store.Save(u)
	return u, err
}

func (m *DefaultManager) Get(ID string) (*User, error) {
	return m.store.Get(ID)
}

func (m *DefaultManager) GetAll() ([]*User, error) {
	u, _, err := m.store.All(0, 10)
	return u, err
}

func (m *DefaultManager) LoadUsers(file string, fs afero.Fs) error {
	log.Infof("loading user accounts from %s", file)
	data, err := afero.ReadFile(fs, file)
	if err != nil {
		return err
	}
	var users []*User
	err = yaml.Unmarshal(data, &users)
	if err != nil {
		return err
	}
	for _, u := range users {
		err = m.store.Save(u)
		if err != nil {
			log.Errorf("error saving user %s: %s", u, err.Error())
		}
	}
	log.Infof("loaded %d users from %s", len(users), file)
	return nil
}

func parseToken(tokenString string) (res *Claims, err error) {
	var ok bool
	var token *jwt.Token
	res = new(Claims)
	if token, err = jwt.ParseWithClaims(tokenString, res, func(token *jwt.Token) (interface{}, error) {
		if _, ok = token.Method.(*jwt.SigningMethodHMAC); !ok {
			//fmt.Sprintf("Unexpected signing method: %v", token.Header["alg"])
			return nil, ErrBadRequest
		}
		return secret, nil
	}); err != nil {
		return res, err
	}

	if res, ok = token.Claims.(*Claims); !ok {
		err = ErrBadRequest
	}
	return res, err

}

//BuildToken builds a JWT token with custom claims
func BuildToken(username, fullName string, rights int) (string, error) {
	ttl := time.Now().Add(time.Duration(30) * time.Minute)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Username:    username,
		Name:        fullName,
		Permissions: rights,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: ttl.Unix(),
		},
	})
	return token.SignedString(secret)
}
