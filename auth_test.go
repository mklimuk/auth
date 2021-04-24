package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestManager_CreateUser(t *testing.T) {
	s := &storeMock{}
	s.On("SaveUser", mock.AnythingOfType("auth.User")).Return(nil)
	m := New(s, s, Opts{PasswordSecret: []byte("m!ch4l_"), TokenTTL: 30 * time.Second})
	usr := User{Username: "test", Password: "test123", Name: "test test", Scope: 7}
	err := m.CreateUser(usr)
	assert.NoError(t, err)
	s.AssertExpectations(t)
}

func TestManager_Login(t *testing.T) {
	s := &storeMock{}
	s.On("GetUserByUsername", "michal", mock.AnythingOfType("*auth.User")).Run(func(a mock.Arguments) {
		u := a[1].(*User)
		u.Username = "michal"
		u.Name = "Michal Klimuk"
		u.Password = "$2a$10$H9Bs2caL.R1mJNeNtJs07uGUtrWXwoHwWbQtwZ0yBEvZ9jJ1o4d26"
		u.Scope = 7
	}).Return(nil)
	m := New(s, s, Opts{TokenTTL: 30 * time.Second, PasswordSecret: []byte("m!ch4l_")})
	token, err := m.Login("michal", "test123", &User{})
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestManager_BuildToken(t *testing.T) {
	a, err := buildJwt("u1", "michal", "klimuk", []byte("m!ch4l_"), 30*time.Second, 7)
	assert.NoError(t, err)
	time.Sleep(1001 * time.Millisecond)
	b, err := buildJwt("u1", "michal", "klimuk", []byte("m!ch4l_"), 30*time.Second, 7)
	assert.NoError(t, err)
	assert.NotEqual(t, a, b)
}

func TestManager_DecodeToken(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODUzNDUzOTEsInVzZXJuYW1lIjoibWljaGFsIiwibmFtZSI6Ik1pY2hhbCBLbGltdWsiLCJwZXJtaXNzaW9ucyI6N30.a-Uh1Z_5m7Jy3GBJbjAZfYqC9uYaIFhM4HKnNb5fwZ4"
	c := newClaims()
	defer returnClaims(c)
	err := parseJwt(token, []byte("m!ch4l_"), c)
	assert.Error(t, err)
	assert.Equal(t, "michal", c.Username)
	token, err = buildJwt("u1", "mklimuk", "Michal", []byte("m!ch4l_"), 30*time.Second, 7)
	assert.NoError(t, err)
	err = parseJwt(token, []byte("m!ch4l_"), c)
	assert.NoError(t, err)
	assert.Equal(t, "mklimuk", c.Username)
}

func TestManager_ValidateToken(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODUzNDUzOTEsInVzZXJuYW1lIjoibWljaGFsIiwibmFtZSI6Ik1pY2hhbCBLbGltdWsiLCJwZXJtaXNzaW9ucyI6N30.a-Uh1Z_5m7Jy3GBJbjAZfYqC9uYaIFhM4HKnNb5fwZ4"
	c := newClaims()
	defer returnClaims(c)
	u := newUser()
	defer returnUser(u)
	s := &storeMock{}
	m := New(s, s, Opts{PasswordSecret: []byte("m!ch4l_"), TokenTTL: 30 * time.Second})
	s.On("GetUserToken", token).Return(ErrNotFound).Once()
	_, err := m.ValidateToken(token, u, c, 0xFF, true)
	assert.Error(t, err)
	token, err = buildJwt("u1", "mklimuk", "Michal", []byte("m!ch4l_"), 30*time.Second, 7)
	s.On("GetUserToken", token).Return(ErrNotFound).Once()
	s.On("GetUserByUsername", "mklimuk", mock.Anything).Run(func(args mock.Arguments) {
		user := args.Get(1).(*User)
		user.Username = "mklimuk"
		user.Scope = 7
	}).Return(nil).Once()
	updated, err := m.ValidateToken(token, u, c, 0xFF, true)
	assert.NoError(t, err)
	assert.NotEmpty(t, updated)
	s.On("GetUserToken", updated).Return(ErrNotFound).Once()
	s.On("GetUserByUsername", "mklimuk", mock.Anything).Run(func(args mock.Arguments) {
		user := args.Get(1).(*User)
		user.Username = "mklimuk"
		user.Scope = 7
	}).Return(nil).Once()
	updated, err = m.ValidateToken(updated, u, c, 0xFF, true)
	assert.NoError(t, err)
	assert.NotEmpty(t, updated)
	assert.Equal(t, "mklimuk", c.Username)
	assert.Equal(t, "u1", c.Id)
	s.AssertExpectations(t)
}

type storeMock struct {
	mock.Mock
}

func (m *storeMock) SaveUser(u User) error {
	args := m.Called(u)
	return args.Error(0)
}

func (m *storeMock) GetUserToken(ID string, _ *Token) error {
	args := m.Called(ID)
	return args.Error(0)
}

func (m *storeMock) SaveToken(t Token) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *storeMock) GetUser(ID string, u *User) error {
	args := m.Called(ID, u)
	return args.Error(0)
}

func (m *storeMock) GetUserByUsername(username string, u *User) error {
	args := m.Called(username, u)
	return args.Error(0)
}

func (m *storeMock) DeleteUser(ID string) error {
	args := m.Called(ID)
	return args.Error(0)
}

func (m *storeMock) AllUsers(page, pageSize int) ([]*User, error) {
	args := m.Called(page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*User), args.Error(1)
}
