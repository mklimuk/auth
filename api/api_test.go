package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	log "github.com/Sirupsen/logrus"
	"github.com/gin-gonic/gin"
	"github.com/mklimuk/auth/config"
	"github.com/mklimuk/auth/user"
	"github.com/mklimuk/goerr"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type APITestSuite struct {
	suite.Suite
	router *gin.Engine
	usr    user.ManagerMock
	serv   *httptest.Server
}

func (suite *APITestSuite) SetupSuite() {
	log.SetLevel(log.DebugLevel)
	suite.usr = user.ManagerMock{}
	u := NewUserAPI(&suite.usr)
	c := NewControlAPI()
	suite.router = gin.New()
	u.AddRoutes(suite.router)
	c.AddRoutes(suite.router)
	suite.serv = httptest.NewServer(suite.router)
}

func (suite *APITestSuite) TearDownSuite() {
	suite.serv.Close()
}

func (suite *APITestSuite) TestHealth() {
	a := assert.New(suite.T())
	res, err := http.Get(fmt.Sprintf("%s%s", suite.serv.URL, "/health"))
	a.NoError(err)
	a.Equal(http.StatusOK, res.StatusCode)
}

func (suite *APITestSuite) TestVersion() {
	a := assert.New(suite.T())
	config.Ver = config.Version{Version: "0.1.0"}
	res, err := http.Get(fmt.Sprintf("%s%s", suite.serv.URL, "/version"))
	a.NoError(err)
	a.Equal(http.StatusOK, res.StatusCode)
}

func (suite *APITestSuite) TestCreateTemplate() {
	a := assert.New(suite.T())
	// test no body (parse error)
	res, err := http.Post(fmt.Sprintf("%s%s", suite.serv.URL, "/login"), "application/x.login.req+json", nil)
	a.NoError(err)
	a.Equal(http.StatusBadRequest, res.StatusCode)
	req := &user.User{Username: "test1", Password: "pass"}
	var b []byte
	b, err = json.Marshal(&req)
	a.NoError(err)
	// test unauthorized
	suite.usr.On("Login", "test1", "pass").Return("", goerr.NewError("unauthorized", goerr.Unauthorized)).Once()
	res, err = http.Post(fmt.Sprintf("%s%s", suite.serv.URL, "/login"), "application/x.login.req+json", bytes.NewReader(b))
	a.NoError(err)
	a.Equal(http.StatusUnauthorized, res.StatusCode)
	// test internal error
	suite.usr.On("Login", "test1", "pass").Return("", errors.New("generic error")).Once()
	res, err = http.Post(fmt.Sprintf("%s%s", suite.serv.URL, "/login"), "application/x.login.req+json", bytes.NewReader(b))
	a.NoError(err)
	a.Equal(http.StatusInternalServerError, res.StatusCode)
	// happy path
	suite.usr.On("Login", "test1", "pass").Return("abcd", nil).Once()
	res, err = http.Post(fmt.Sprintf("%s%s", suite.serv.URL, "/login"), "application/x.login.req+json", bytes.NewReader(b))
	a.NoError(err)
	a.Equal(http.StatusOK, res.StatusCode)
}

func TestAPITestSuite(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}
