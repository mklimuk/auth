package auth

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/oklog/ulid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"
	yaml "gopkg.in/yaml.v2"
)

//var secret []byte

var entropy *rand.Rand

var userPool *sync.Pool
var claimsPool *sync.Pool

func init() {
	t := time.Unix(1000000, 0)
	entropy = rand.New(rand.NewSource(t.UnixNano()))
	userPool = &sync.Pool{
		New: func() interface{} {
			return new(User)
		},
	}
	claimsPool = &sync.Pool{
		New: func() interface{} {
			return new(Claims)
		},
	}
}

var empty = ""

func newUser() *User {
	return userPool.New().(*User)
}

func releaseUser(u *User) {
	*u = User{}
	userPool.Put(u)
}

func newClaims() *Claims {
	return claimsPool.New().(*Claims)
}

func returnClaims(c *Claims) {
	*c = Claims{}
	claimsPool.Put(c)
}

var (
	ErrUnauthorized  = fmt.Errorf("unauthorized")
	ErrNotFound      = fmt.Errorf("user not found")
	ErrExists        = fmt.Errorf("user exists")
	ErrBadRequest    = fmt.Errorf("bad request")
	ErrWrongUserPass = fmt.Errorf("wrong username or password")
)

type ctx int

const (
	ctxUser ctx = iota
)

type userContext struct {
	User   *User
	Claims *Claims
}

func Wrap(ctx context.Context, user *User, cs *Claims) context.Context {
	return context.WithValue(ctx, ctxUser, &userContext{Claims: cs, User: user})
}

func Get(c context.Context) User {
	u := c.Value(ctxUser)
	if u == nil {
		panic("[auth] misuse of Get method; no user in context")
	}
	return *u.(*userContext).User
}

//User contains user properties
type User struct {
	ID       string `json:"id" yaml:"id,omitempty" storm:"unique"`
	Username string `json:"username" yaml:"username" storm:"unique"`
	Name     string `json:"name" yaml:"name"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	Passcode string `json:"passcode,omitempty" yaml:"passcode,omitempty"`
	Rigths   int    `json:"rights" yaml:"rights"`
}

//Claims contains specific claims used in the auth system
type Claims struct {
	jwt.StandardClaims
	Username    string `json:"username"`
	Name        string `json:"name"`
	Permissions int    `json:"permissions"`
}

type Opts struct {
	TokenTTL           time.Duration
	PasswordSecret     []byte
	AllowPasscodeLogin bool
}

type DefaultManager struct {
	store Store
	opts  Opts
}

//NewDefaultManager returns a default user manager
func NewDefaultManager(store Store, opts Opts) *DefaultManager {
	m := &DefaultManager{store, opts}
	return m
}

func (m *DefaultManager) Login(u *User) (string, error) {
	if u.Username == "" {
		if m.opts.AllowPasscodeLogin && u.Passcode != "" {
			return m.passcodeLogin(u)
		}
		return "", ErrWrongUserPass
	}
	return m.userPasswordLogin(u)
}

func (m *DefaultManager) userPasswordLogin(u *User) (string, error) {
	log.Infof("[auth-user] signin request from user %s", u.Username)
	pass := u.Password
	err := m.store.ByUsername(u.Username, u)
	if err != nil {
		return "", err
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(pass))
	if err != nil {
		log.Infof("[auth-user] unsuccessful login for %s", u.Username)
		return "", ErrWrongUserPass
	}
	return BuildToken(u.ID, u.Username, u.Name, m.opts.PasswordSecret, m.opts.TokenTTL, u.Rigths)
}

//passcodeLogin uses sha3-256 fixed hash to perform user login
func (m *DefaultManager) passcodeLogin(u *User) (string, error) {
	pwddata := sha3.Sum256([]byte(u.Passcode))
	pwd := hex.EncodeToString(pwddata[:])
	err := m.store.ByPasscode(pwd, u)
	if err != nil {
		return "", err
	}
	// if the user was found we simply return the token
	return BuildToken(u.ID, u.Username, u.Name, m.opts.PasswordSecret, m.opts.TokenTTL, u.Rigths)
}

func (m *DefaultManager) Logout(User) error {
	// TODO: add logout hooks support
	return nil
}

func (m *DefaultManager) ValidToken(token string) bool {
	c := newClaims()
	defer returnClaims(c)
	_, err := m.CheckToken(token, false, c)
	return err == nil
}

func (m *DefaultManager) CheckToken(token string, update bool, c *Claims) (string, error) {
	err := parseToken(token, m.opts.PasswordSecret, c)
	if err != nil {
		return token, err
	}
	if update {
		updated, err := BuildToken(c.Id, c.Username, c.Name, m.opts.PasswordSecret, m.opts.TokenTTL, c.Permissions)
		if err != nil {
			return token, err
		}
		return updated, nil
	}
	return token, nil
}

func (m *DefaultManager) Create(u *User) error {
	if u.Passcode == "" && u.Password == "" {
		return ErrBadRequest
	}
	if u.Password != "" {
		ID, err := ulid.New(ulid.Timestamp(time.Now()), entropy)
		if err != nil {
			return err
		}
		u.ID = ID.String()
		pwd, err := bcrypt.GenerateFromPassword([]byte(u.Password), 10)
		if err != nil {
			return err
		}
		u.Password = string(pwd)
	}
	if u.Passcode != "" {
		pwddata := sha3.Sum256([]byte(u.Passcode))
		u.Passcode = hex.EncodeToString(pwddata[:])
	}
	if m.store == nil {
		return nil
	}
	return m.store.Save(u)
}

func (m *DefaultManager) Get(ID string, u *User) error {
	err := m.store.Get(ID, u)
	if err != nil {
		return err
	}
	return err
}

func (m *DefaultManager) GetAll() ([]*User, error) {
	return m.store.All(0, 10)
}

func (m *DefaultManager) LoadUsers(file string, fs afero.Fs) error {
	log.Infof("[auth-user] loading user accounts from %s", file)
	data, err := afero.ReadFile(fs, file)
	if err != nil {
		return err
	}
	var users []*User
	err = yaml.Unmarshal(data, &users)
	if err != nil {
		return err
	}
	count := 0
	for _, u := range users {
		ID, err := ulid.New(ulid.Timestamp(time.Now()), entropy)
		if err != nil {
			log.Errorf("[auth-user] error creating user %s: %v", u.Username, err)
			continue
		}
		u.ID = ID.String()
		err = m.store.Save(u)
		if err != nil {
			log.Errorf("[auth-user] error creating user %s: %v", u.Username, err)
			continue
		}
		count++
	}

	log.Infof("[auth-user] loaded %d users from %s", count, file)
	return nil
}

func parseToken(tokenString string, secret []byte, c *Claims) error {
	_, err := jwt.ParseWithClaims(tokenString, c, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrBadRequest
		}
		return secret, nil
	})
	if err != nil {
		return errors.Wrap(err, "could not parse token")
	}

	now := time.Now()
	deadline := time.Unix(c.ExpiresAt, 0).In(now.Location())
	if deadline.Before(now) {
		return ErrUnauthorized
	}
	return nil
}

//BuildToken builds a JWT token with custom claims
func BuildToken(id, username, fullName string, secret []byte, validity time.Duration, rights int) (string, error) {
	ttl := time.Now().Add(validity)
	c := newClaims()
	defer returnClaims(c)
	c.Id = id
	c.Username = username
	c.Name = fullName
	c.Permissions = rights
	c.ExpiresAt = ttl.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, *c)
	return token.SignedString(secret)
}
