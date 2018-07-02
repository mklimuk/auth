package user

import (
	"testing"

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
	s := &StoreMock{}
	s.On("Save", mock.AnythingOfType("*user.User")).Return(nil)
	m := NewDefaultManager(s)
	usr := &User{Username: "test", Password: "test123", Name: "test test", Rigths: 7}
	var err error
	_, err = m.Create(usr)
	a.NoError(err)
}

func (suite *ManagerTestSuite) TestLoadUsers() {
	fs := afero.NewMemMapFs()
	err := afero.WriteFile(fs, "/etc/users/user.conf", []byte(userFile), 0600)
	if err != nil {
		suite.FailNow("could not initialize load users test")
	}
	s := &StoreMock{}
	s.On("Save", mock.AnythingOfTypeArgument("*user.User")).Return(nil).Twice()
	m := NewDefaultManager(s)
	err = m.LoadUsers("/etc/users/user.conf", fs)
	suite.NoError(err)
	s.AssertExpectations(suite.T())
}

func (suite *ManagerTestSuite) TestLogin() {
	a := assert.New(suite.T())
	u := &User{
		Username: "michal",
		Name:     "Michal Klimuk",
		Password: "$2a$10$H9Bs2caL.R1mJNeNtJs07uGUtrWXwoHwWbQtwZ0yBEvZ9jJ1o4d26",
		Rigths:   7,
	}
	s := &StoreMock{}
	s.On("ByUsername", "michal").Return(u, nil)
	m := NewDefaultManager(s)
	token, err := m.Login("michal", "test123")
	a.NoError(err)
	a.NotEmpty(token)
}

func (suite *ManagerTestSuite) TestDecodeToken() {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODUzNDUzOTEsInVzZXJuYW1lIjoibWljaGFsIiwibmFtZSI6Ik1pY2hhbCBLbGltdWsiLCJwZXJtaXNzaW9ucyI6N30.a-Uh1Z_5m7Jy3GBJbjAZfYqC9uYaIFhM4HKnNb5fwZ4"
	c, err := parseToken(token)
	a := assert.New(suite.T())
	a.Error(err)
	a.Equal("michal", c.Username)
	token, err = BuildToken("mklimuk", "Michal", 7)
	a.NoError(err)
	c, err = parseToken(token)
	a.NoError(err)
	a.Equal("mklimuk", c.Username)
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
