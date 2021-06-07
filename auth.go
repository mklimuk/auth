package auth

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/oklog/ulid"
	"golang.org/x/crypto/bcrypt"
)

var _ UserLoginHandler = &Auth{}
var _ TokenValidator = &Auth{}
var _ TokenGenerator = &Auth{}
var _ TokenReader = &Auth{}
var _ TokenRemover = &Auth{}

var entropy *rand.Rand

var claimsPool *sync.Pool

func init() {
	t := time.Unix(1000000, 0)
	entropy = rand.New(rand.NewSource(t.UnixNano()))
	claimsPool = &sync.Pool{
		New: func() interface{} {
			return &Claims{}
		},
	}
}

func newClaims() *Claims {
	return claimsPool.New().(*Claims)
}

func returnClaims(c *Claims) {
	*c = Claims{}
	claimsPool.Put(c)
}

var (
	ErrUnauthorized  = errors.New("unauthorized")
	ErrNotFound      = errors.New("user not found")
	ErrExists        = errors.New("user exists")
	ErrWrongUserPass = errors.New("wrong username or password")
	ErrTokenExpired  = errors.New("token expired")
)

//Claims contains specific claims used in the auth system
type Claims struct {
	jwt.StandardClaims
	Username string `json:"username"`
	Name     string `json:"name"`
	Scope    Scope  `json:"scope"`
}

type Opts struct {
	TokenTTL       time.Duration
	PasswordSecret []byte
}

type UserStore interface {
	SaveUser(User) error
	GetUser(string, *User) error
	GetUserByUsername(string, *User) error
	DeleteUser(string) error
	AllUsers(page, pageSize int) ([]*User, error)
}

type UserTokenStore interface {
	GetUserToken(string, *Token) error
	GetUserTokenByValue(string, *Token) error
	GetUserTokens(user string) ([]Token, error)
	DeleteUserToken(id string) error
	SaveUserToken(Token) error
}

var _ UserReadWriter = &Auth{}

type Auth struct {
	users  UserStore
	tokens UserTokenStore
	opts   Opts
}

//New returns a default authentication service
func New(users UserStore, tokens UserTokenStore, opts Opts) *Auth {
	return &Auth{users: users, tokens: tokens, opts: opts}
}

func (a *Auth) Login(username, password string) (string, error) {
	u := newUser()
	defer returnUser(u)
	err := a.users.GetUserByUsername(username, u)
	if err != nil {
		return "", err
	}
	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		return "", ErrWrongUserPass
	}
	return buildJwt(u.ID, u.Username, u.Name, a.opts.PasswordSecret, a.opts.TokenTTL, u.Scope)
}

func (a *Auth) ValidateToken(token string, u *User, cs *Claims, update bool) (string, error) {
	tok := newToken()
	defer releaseToken(tok)
	err := a.tokens.GetUserTokenByValue(token, tok)
	// if token found, validate
	if err != nil {
		if err != ErrNotFound {
			return "", fmt.Errorf("could not fetch token: %w", err)
		}
		err = parseJwt(token, a.opts.PasswordSecret, cs)
		if err != nil {
			return token, fmt.Errorf("could not parse token: %w", err)
		}
	} else {
		if !tok.ExpiresAt.IsZero() && tok.ExpiresAt.Before(time.Now()) {
			return "", ErrTokenExpired
		}
		// we need to populate claims by hand
		cs.Id = tok.Owner
		now := time.Now()
		cs.IssuedAt = now.Unix()
		cs.Scope = tok.Scope
		cs.ExpiresAt = now.Add(a.opts.TokenTTL).Unix()
	}
	err = a.users.GetUser(cs.Id, u)
	if err != nil {
		return token, fmt.Errorf("could not get user: %w", err)
	}
	if !update {
		return token, nil
	}
	return u.toJwt(a.opts.PasswordSecret, u.Scope, a.opts.TokenTTL)
}

func (a *Auth) Logout(User) error {
	// TODO: add logout hooks support
	return nil
}

func (a *Auth) CreateUser(u User) error {
	ID, err := ulid.New(ulid.Timestamp(time.Now()), entropy)
	if err != nil {
		return fmt.Errorf("could not init generator: %w", err)
	}
	u.ID = ID.String()
	pwd, err := bcrypt.GenerateFromPassword([]byte(u.Password), 10)
	if err != nil {
		return fmt.Errorf("could not generate password: %w", err)
	}
	u.Password = string(pwd)

	if a.users == nil {
		return nil
	}
	return a.users.SaveUser(u)
}

func (a *Auth) GetUser(ID string, u *User) error {
	err := a.users.GetUser(ID, u)
	if err != nil {
		return err
	}
	return err
}

func (a *Auth) GetAllUsers() ([]*User, error) {
	return a.users.AllUsers(0, 10)
}

func (a *Auth) GenerateUserToken(owner, description string, scope Scope, expires time.Time) (Token, error) {
	token, err := generateToken(owner, description, scope, expires, 24)
	if err != nil {
		return Token{}, fmt.Errorf("could not generate token: %w", err)
	}
	err = a.tokens.SaveUserToken(token)
	if err != nil {
		return Token{}, fmt.Errorf("could not save token: %w", err)
	}
	return token, nil
}

func (a *Auth) GetUserTokens(user string) ([]Token, error) {
	return a.tokens.GetUserTokens(user)
}

func (a *Auth) GetUserToken(id string, t *Token) error {
	return a.tokens.GetUserToken(id, t)
}

func (a *Auth) DeleteUserToken(id string, u *User) error {
	tok := newToken()
	defer releaseToken(tok)
	err := a.tokens.GetUserToken(id, tok)
	if err != nil {
		return fmt.Errorf("could not verify token: %w", err)
	}
	if tok.Owner != u.ID {
		return ErrUnauthorized
	}
	return a.tokens.DeleteUserToken(id)
}
