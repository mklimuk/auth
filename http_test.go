package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	log "github.com/sirupsen/logrus"

	"github.com/stretchr/testify/suite"
)

type APITestSuite struct {
	suite.Suite
}

func (suite *APITestSuite) SetupSuite() {
	log.SetLevel(log.DebugLevel)
}

func testCtxHandler(suite *APITestSuite) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := Get(r.Context())
		if suite.NotNil(u) {
			suite.Equal("test1", u.Username)
		}
	}
}
func (suite *APITestSuite) TestProtected() {
	auth := &managerMock{}
	router := http.NewServeMux()
	router.Handle("/", AuthMiddleware(auth)(testCtxHandler(suite)))
	router.Handle("/login", LoginHandler(auth))
	serv := httptest.NewServer(router)
	defer serv.Close()
	res, err := http.Get(fmt.Sprintf("%s%s", serv.URL, "/"))
	if !suite.NoError(err) {
		suite.FailNow("unexpected error: %s", err.Error())
	}
	if !suite.Equal(http.StatusUnauthorized, res.StatusCode) {
		defer res.Body.Close()
		io.Copy(os.Stdout, res.Body)
		suite.FailNow("unexpected response status", "should be 401 but received %d", res.StatusCode)
	}
	req := &User{Username: "test1", Password: "pass"}
	b, err := json.Marshal(&req)
	auth.On("Login", mock.AnythingOfType("*auth.User")).Return("abcd", nil).Once()
	htc := &http.Client{Timeout: 100 * time.Millisecond}
	r, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s%s", serv.URL, "/login"), bytes.NewReader(b))
	if !suite.NoError(err) {
		suite.FailNow("error creating request")
	}
	r.Header.Set("Content-Type", "application/x.login.req+json")
	res, err = htc.Do(r)
	if !suite.NoError(err) {
		suite.FailNow("unexpected error: %s", err.Error())
	}
	if !suite.Equal(http.StatusOK, res.StatusCode) {
		defer res.Body.Close()
		io.Copy(os.Stdout, res.Body)
		suite.FailNow("unexpected response status", "should be 200 but received %d", res.StatusCode)
	}
	t := res.Header.Get("Authorization")
	suite.NotEmpty(t)
	token := strings.TrimPrefix(t, "Bearer ")
	suite.NotEmpty(token)
	// test using received token
	r, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%s%s", serv.URL, "/testctx"), nil)
	if !suite.NoError(err) {
		suite.FailNow("error creating request")
	}
	r.Header.Set("Authorization", t)
	// initial check token validates the token
	auth.On("CheckToken", token, true, mock.AnythingOfType("*auth.Claims")).Run(func(args mock.Arguments) {
		args.Get(2).(*Claims).Id = "uid1"
	}).Return(token, nil).Once()
	auth.On("Get", "uid1", mock.AnythingOfType("*auth.User")).Run(func(a mock.Arguments) {
		a[1].(*User).Username = "test1"
	}).Return(nil).Once()
	res, err = htc.Do(r)
	if !suite.NoError(err) {
		suite.FailNow("unexpected error", err.Error())
	}
	if !suite.Equal(http.StatusOK, res.StatusCode) {
		defer res.Body.Close()
		io.Copy(os.Stdout, res.Body)
		suite.FailNow("unexpected response status", "should be 200 but received %d", res.StatusCode)
	}
	auth.AssertExpectations(suite.T())
}

func (suite *APITestSuite) TestInterfaces() {
	a := &DefaultManager{}
	var login UserLoginHandler
	var logout UserLogoutHandler
	var reader UserReader
	var admin UserAdmin
	var checker TokenChecker
	var valid TokenValidator
	login = a
	logout = a
	reader = a
	admin = a
	checker = a
	valid = a
	log.Println(login, logout, reader, admin, checker, valid)
}

func (suite *APITestSuite) TestLogin() {
	auth := &managerMock{}
	router := http.NewServeMux()
	router.Handle("/login", LoginHandler(auth))
	serv := httptest.NewServer(router)
	defer serv.Close()
	// test no body (parse error)
	res, err := http.Post(fmt.Sprintf("%s%s", serv.URL, "/login"), "application/x.login.req+json", nil)
	suite.NoError(err)
	suite.Equal(http.StatusBadRequest, res.StatusCode)
	req := &User{Username: "test1", Password: "pass"}
	b, err := json.Marshal(&req)
	suite.NoError(err)
	// test unauthorized
	auth.On("Login", mock.AnythingOfType("*auth.User")).Return("", ErrWrongUserPass).Once()
	res, err = http.Post(fmt.Sprintf("%s%s", serv.URL, "/login"), "application/x.login.req+json", bytes.NewReader(b))
	if suite.NoError(err) {
		if !suite.Equal(http.StatusUnauthorized, res.StatusCode) {
			defer res.Body.Close()
			io.Copy(os.Stdout, res.Body)
			suite.FailNow("unexpected response status", "should be 401 but received %d", res.StatusCode)
		}
	}
	// test internal error
	auth.On("Login", mock.AnythingOfType("*auth.User")).Return("", errors.New("generic error")).Once()
	res, err = http.Post(fmt.Sprintf("%s%s", serv.URL, "/login"), "application/x.login.req+json", bytes.NewReader(b))
	suite.NoError(err)
	suite.Equal(http.StatusInternalServerError, res.StatusCode)
	// happy path
	auth.On("Login", mock.AnythingOfType("*auth.User")).Return("abcd", nil).Once()
	res, err = http.Post(fmt.Sprintf("%s%s", serv.URL, "/login"), "application/x.login.req+json", bytes.NewReader(b))
	suite.NoError(err)
	suite.Equal(http.StatusOK, res.StatusCode)
}

func (suite *APITestSuite) TestCheckToken() {
	// test no body (parse error)
	auth := &managerMock{}
	router := http.NewServeMux()
	router.Handle("/token/check", CheckTokenHandler(auth))
	serv := httptest.NewServer(router)
	defer serv.Close()
	htc := &http.Client{Timeout: 100 * time.Millisecond}
	r, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s%s", serv.URL, "/token/check"), nil)
	suite.NoError(err)
	r.Header.Set("Content-Type", "application/x.token.check+json")
	res, err := htc.Do(r)
	suite.NoError(err)
	suite.Equal(http.StatusBadRequest, res.StatusCode)
	req := &checkRequest{
		Token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODUzNDUzOTEsInVzZXJuYW1lIjoibWljaGFsIiwibmFtZSI6Ik1pY2hhbCBLbGltdWsiLCJwZXJtaXNzaW9ucyI6N30.a-Uh1Z_5m7Jy3GBJbjAZfYqC9uYaIFhM4HKnNb5fwZ4",
		Update: true,
	}
	var b []byte
	b, err = json.Marshal(&req)
	suite.NoError(err)
	// test unauthorized
	auth.On("CheckToken", req.Token, req.Update, mock.AnythingOfType("*auth.Claims")).Run(func(args mock.Arguments) {
		args.Get(2).(*Claims).Username = "mklimuk"
	}).Return(req.Token, fmt.Errorf("unauthorized")).Once()
	r, err = http.NewRequest(http.MethodPut, fmt.Sprintf("%s%s", serv.URL, "/token/check"), bytes.NewReader(b))
	suite.NoError(err)
	r.Header.Set("Content-Type", "application/x.token.check+json")
	res, err = htc.Do(r)
	if suite.NoError(err) {
		if !suite.Equal(http.StatusUnauthorized, res.StatusCode) {
			defer res.Body.Close()
			io.Copy(os.Stdout, res.Body)
			suite.FailNow("unexpected response status", "should be 401 but received %d", res.StatusCode)
		}
	}
	// test internal error
	auth.On("CheckToken", req.Token, req.Update, mock.AnythingOfType("*auth.Claims")).Run(func(args mock.Arguments) {
		args.Get(2).(*Claims).Username = "mklimuk"
	}).Return(req.Token, errors.New("dummy")).Once()
	r, err = http.NewRequest(http.MethodPut, fmt.Sprintf("%s%s", serv.URL, "/token/check"), bytes.NewReader(b))
	suite.NoError(err)
	r.Header.Set("Content-Type", "application/x.token.check+json")
	res, err = htc.Do(r)
	if suite.NoError(err) {
		suite.Equal(http.StatusUnauthorized, res.StatusCode)
	}
	// happy path
	var token string
	token, err = BuildToken("u1", "mklimuk", "Michal", []byte("m!ch4l_"), 30*time.Second, 3)
	suite.NoError(err)
	auth.On("CheckToken", req.Token, req.Update, mock.AnythingOfType("*auth.Claims")).Run(func(args mock.Arguments) {
		args.Get(2).(*Claims).Username = "mklimuk"
	}).Return(token, nil).Once()
	r, err = http.NewRequest(http.MethodPut, fmt.Sprintf("%s%s", serv.URL, "/token/check"), bytes.NewReader(b))
	suite.NoError(err)
	r.Header.Set("Content-Type", "application/x.token.check+json")
	res, err = htc.Do(r)
	if suite.NoError(err) {
		suite.Equal(http.StatusOK, res.StatusCode)
	}
}

func TestAPITestSuite(t *testing.T) {
	suite.Run(t, new(APITestSuite))
}

type managerMock struct {
	mock.Mock
}

//Login is a mocked method
func (m *managerMock) Login(u *User) (string, error) {
	args := m.Called(u)
	return args.String(0), args.Error(1)
}

//Create is a mocked method
func (m *managerMock) Create(u *User) (*User, error) {
	args := m.Called(u)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *managerMock) Get(ID string, u *User) error {
	args := m.Called(ID, u)
	return args.Error(0)
}

//GetAll is a mocked method
func (m *managerMock) GetAll() ([]*User, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*User), args.Error(1)
}

//CheckToken is a mocked method
func (m *managerMock) CheckToken(token string, update bool, c *Claims) (string, error) {
	args := m.Called(token, update, c)
	return args.String(0), args.Error(1)
}

func (m *managerMock) ValidToken(token string) bool {
	args := m.Called(token)
	return args.Bool(0)
}
