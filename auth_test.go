package auth

import (
	"testing"
	"time"

	"github.com/spf13/afero"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type ManagerTestSuite struct {
	suite.Suite
}

func (suite *ManagerTestSuite) SetupSuite() {
	log.SetLevel(log.DebugLevel)
}

func (suite *ManagerTestSuite) TestCreate() {
	a := assert.New(suite.T())
	s := &storeMock{}
	s.On("Save", mock.AnythingOfType("*auth.User")).Return(nil)
	m := NewDefaultManager(s, Opts{PasswordSecret: []byte("m!ch4l_"), TokenTTL: 30 * time.Second})
	usr := &User{Username: "test", Password: "test123", Name: "test test", Rigths: 7}
	err := m.Create(usr)
	a.NoError(err)
}

func (suite *ManagerTestSuite) TestLoadUsers() {
	fs := afero.NewMemMapFs()
	err := afero.WriteFile(fs, "/etc/users/conf", []byte(userFile), 0600)
	if err != nil {
		suite.FailNow("could not initialize load users test")
	}
	s := &storeMock{}
	s.On("Save", mock.AnythingOfTypeArgument("*auth.User")).Return(nil).Twice()
	m := NewDefaultManager(s, Opts{PasswordSecret: []byte("m!ch4l_"), TokenTTL: 30 * time.Second})
	err = m.LoadUsers("/etc/users/conf", fs)
	suite.NoError(err)
	s.AssertExpectations(suite.T())
}

func (suite *ManagerTestSuite) TestLogin() {
	s := &storeMock{}
	s.On("ByUsername", "michal", mock.AnythingOfType("*auth.User")).Run(func(a mock.Arguments) {
		u := a[1].(*User)
		u.Username = "michal"
		u.Name = "Michal Klimuk"
		u.Password = "$2a$10$H9Bs2caL.R1mJNeNtJs07uGUtrWXwoHwWbQtwZ0yBEvZ9jJ1o4d26"
		u.Rigths = 7
	}).Return(nil)
	m := NewDefaultManager(s, Opts{TokenTTL: 30 * time.Second, PasswordSecret: []byte("m!ch4l_"), AllowPasscodeLogin: false})
	token, err := m.Login(&User{Username: "michal", Password: "test123"})
	suite.NoError(err)
	suite.NotEmpty(token)
	// passcode login
	s.On("ByUsername", "", mock.AnythingOfType("*auth.User")).Return(ErrNotFound).Once()
	token, err = m.Login(&User{Username: "", Password: "test123"})
	suite.Equal(ErrWrongUserPass, err)
	suite.Empty(token)
	m.opts.AllowPasscodeLogin = true
	s.On("ByPasscode", "3054762b0a8b31adfe79efb3bc7718624627cc99c7c8f39bfa591ce6854ac05d", mock.AnythingOfType("*auth.User")).Run(func(a mock.Arguments) {
		u := a[1].(*User)
		u.Username = "michal"
		u.Name = "Michal Klimuk"
		u.Password = "$2a$10$H9Bs2caL.R1mJNeNtJs07uGUtrWXwoHwWbQtwZ0yBEvZ9jJ1o4d26"
		u.Passcode = "3054762b0a8b31adfe79efb3bc7718624627cc99c7c8f39bfa591ce6854ac05d"
		u.Rigths = 7
	}).Return(nil).Once()
	usr := &User{Username: "", Passcode: "test123"}
	token, err = m.Login(usr)
	suite.NoError(err)
	suite.NotEmpty(token)
	suite.Equal("michal", usr.Username)
}

func (suite *ManagerTestSuite) TestBuildToken() {
	a, err := BuildToken("u1", "michal", "klimuk", []byte("m!ch4l_"), 30*time.Second, 7)
	suite.NoError(err)
	time.Sleep(1001 * time.Millisecond)
	b, err := BuildToken("u1", "michal", "klimuk", []byte("m!ch4l_"), 30*time.Second, 7)
	suite.NoError(err)
	suite.NotEqual(a, b)
}

func (suite *ManagerTestSuite) TestDecodeToken() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODUzNDUzOTEsInVzZXJuYW1lIjoibWljaGFsIiwibmFtZSI6Ik1pY2hhbCBLbGltdWsiLCJwZXJtaXNzaW9ucyI6N30.a-Uh1Z_5m7Jy3GBJbjAZfYqC9uYaIFhM4HKnNb5fwZ4"
	c := newClaims()
	defer returnClaims(c)
	err := parseToken(token, []byte("m!ch4l_"), c)
	a := assert.New(suite.T())
	a.Error(err)
	a.Equal("michal", c.Username)
	token, err = BuildToken("u1", "mklimuk", "Michal", []byte("m!ch4l_"), 30*time.Second, 7)
	a.NoError(err)
	err = parseToken(token, []byte("m!ch4l_"), c)
	a.NoError(err)
	a.Equal("mklimuk", c.Username)
}

func (suite *ManagerTestSuite) TestCheckToken() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODUzNDUzOTEsInVzZXJuYW1lIjoibWljaGFsIiwibmFtZSI6Ik1pY2hhbCBLbGltdWsiLCJwZXJtaXNzaW9ucyI6N30.a-Uh1Z_5m7Jy3GBJbjAZfYqC9uYaIFhM4HKnNb5fwZ4"
	c := newClaims()
	defer returnClaims(c)
	m := DefaultManager{opts: Opts{PasswordSecret: []byte("m!ch4l_")}}
	suite.False(m.ValidToken(token))
	t, err := m.CheckToken(token, false, c)
	suite.Error(err)
	suite.Equal(token, t)
	token, err = BuildToken("u1", "mklimuk", "Michal", []byte("m!ch4l_"), 30*time.Second, 7)
	suite.True(m.ValidToken(token))
	suite.NoError(err)
	t, err = m.CheckToken(token, false, c)
	suite.NoError(err)
	suite.Equal("mklimuk", c.Username)
	suite.Equal("u1", c.Id)
	suite.Equal(token, t)
	t, err = m.CheckToken(token, true, c)
	suite.NoError(err)
	suite.Equal("mklimuk", c.Username)
}

func TestManagerTestSuite(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}

const userFile = `
-
  username: michal
  name: Michal Klimuk
  password: $2a$10$v9dAPJH9SD2pi2GGwcY1G.NCBGj83z.keXbZuLaIB47BWXQEDFXp6 #test123
  rights: 7
-
  username: pkp
  name: Operator
  password: $2a$10$IHyW1P2YF.WLCOHZjWcdRuTGsEpJF.zscwskYE0SIm24xvsyK3FyW #lomianki
  rights: 1
`

type storeMock struct {
	mock.Mock
}

func (m *storeMock) Save(u *User) error {
	args := m.Called(u)
	return args.Error(0)
}

func (m *storeMock) Get(ID string, u *User) error {
	args := m.Called(ID, u)
	return args.Error(0)
}
func (m *storeMock) ByUsername(username string, u *User) error {
	args := m.Called(username, u)
	return args.Error(0)
}

func (m *storeMock) ByPasscode(pass string, u *User) error {
	args := m.Called(pass, u)
	return args.Error(0)
}

func (m *storeMock) Delete(ID string) error {
	args := m.Called(ID)
	return args.Error(0)
}

func (m *storeMock) All(page, pageSize int) ([]*User, error) {
	args := m.Called(page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*User), args.Error(1)
}
