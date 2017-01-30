package user

import (
	"testing"

	log "github.com/Sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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
	u := []*User{}
	m := NewManager(u)
	usr := &User{Username: "test", Password: "test123", Name: "test test", Rigths: 7}
	var err error
	_, err = m.Create(usr)
	a.NoError(err)
}

func (suite *ManagerTestSuite) TestLogin() {
	a := assert.New(suite.T())
	u := []*User{
		&User{
			Username: "michal",
			Name:     "Michal Klimuk",
			Password: "$2a$10$H9Bs2caL.R1mJNeNtJs07uGUtrWXwoHwWbQtwZ0yBEvZ9jJ1o4d26",
			Rigths:   7,
		},
	}
	m := NewManager(u)
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
