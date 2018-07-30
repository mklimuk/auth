package api

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

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/mklimuk/auth/user"
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
		u := GetUser(r.Context())
		if suite.NotNil(u) {
			suite.Equal("test1", u.Username)
		}
	}
}
func (suite *APITestSuite) TestProtected() {
	usr := &user.ManagerMock{}
	router := chi.NewRouter()
	router.Route("/", UserAPI(usr))
	protect := router.With(AuthMiddleware(usr))
	protect.Get("/testctx", testCtxHandler(suite))
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
	req := &user.User{Username: "test1", Password: "pass"}
	b, err := json.Marshal(&req)
	usr.On("Login", "test1", "pass").Return("abcd", nil).Once()
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
	usr.On("CheckToken", token, true).Return(token, &user.Claims{StandardClaims: jwt.StandardClaims{Id: "uid1"}}, nil).Once()
	usr.On("Get", "uid1").Return(&user.User{Username: "test1"}, nil).Once()
	res, err = htc.Do(r)
	if !suite.NoError(err) {
		suite.FailNow("unexpected error", err.Error())
	}
	if !suite.Equal(http.StatusOK, res.StatusCode) {
		defer res.Body.Close()
		io.Copy(os.Stdout, res.Body)
		suite.FailNow("unexpected response status", "should be 200 but received %d", res.StatusCode)
	}
	usr.AssertExpectations(suite.T())
}

func (suite *APITestSuite) TestLogin() {
	usr := &user.ManagerMock{}
	router := chi.NewRouter()
	router.Route("/", UserAPI(usr))
	serv := httptest.NewServer(router)
	defer serv.Close()
	// test no body (parse error)
	res, err := http.Post(fmt.Sprintf("%s%s", serv.URL, "/login"), "application/x.login.req+json", nil)
	suite.NoError(err)
	suite.Equal(http.StatusBadRequest, res.StatusCode)
	req := &user.User{Username: "test1", Password: "pass"}
	b, err := json.Marshal(&req)
	suite.NoError(err)
	// test unauthorized
	usr.On("Login", "test1", "pass").Return("", user.ErrWrongUserPass).Once()
	res, err = http.Post(fmt.Sprintf("%s%s", serv.URL, "/login"), "application/x.login.req+json", bytes.NewReader(b))
	if suite.NoError(err) {
		if !suite.Equal(http.StatusUnauthorized, res.StatusCode) {
			defer res.Body.Close()
			io.Copy(os.Stdout, res.Body)
			suite.FailNow("unexpected response status", "should be 401 but received %d", res.StatusCode)
		}
	}
	// test internal error
	usr.On("Login", "test1", "pass").Return("", errors.New("generic error")).Once()
	res, err = http.Post(fmt.Sprintf("%s%s", serv.URL, "/login"), "application/x.login.req+json", bytes.NewReader(b))
	suite.NoError(err)
	suite.Equal(http.StatusInternalServerError, res.StatusCode)
	// happy path
	usr.On("Login", "test1", "pass").Return("abcd", nil).Once()
	res, err = http.Post(fmt.Sprintf("%s%s", serv.URL, "/login"), "application/x.login.req+json", bytes.NewReader(b))
	suite.NoError(err)
	suite.Equal(http.StatusOK, res.StatusCode)
}

func (suite *APITestSuite) TestCheckToken() {
	// test no body (parse error)
	usr := &user.ManagerMock{}
	router := chi.NewRouter()
	router.Route("/", UserAPI(usr))
	serv := httptest.NewServer(router)
	defer serv.Close()
	htc := &http.Client{Timeout: 100 * time.Millisecond}
	r, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s%s", serv.URL, "/token/check"), nil)
	suite.NoError(err)
	r.Header.Set("Content-Type", "application/x.token.check+json")
	res, err := htc.Do(r)
	suite.NoError(err)
	suite.Equal(http.StatusBadRequest, res.StatusCode)
	c := &user.Claims{Username: "mklimuk"}
	req := &checkRequest{
		Token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODUzNDUzOTEsInVzZXJuYW1lIjoibWljaGFsIiwibmFtZSI6Ik1pY2hhbCBLbGltdWsiLCJwZXJtaXNzaW9ucyI6N30.a-Uh1Z_5m7Jy3GBJbjAZfYqC9uYaIFhM4HKnNb5fwZ4",
		Update: true,
	}
	var b []byte
	b, err = json.Marshal(&req)
	suite.NoError(err)
	// test unauthorized
	usr.On("CheckToken", req.Token, req.Update).Return(req.Token, c, fmt.Errorf("unauthorized")).Once()
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
	usr.On("CheckToken", req.Token, req.Update).Return(req.Token, c, errors.New("dummy")).Once()
	r, err = http.NewRequest(http.MethodPut, fmt.Sprintf("%s%s", serv.URL, "/token/check"), bytes.NewReader(b))
	suite.NoError(err)
	r.Header.Set("Content-Type", "application/x.token.check+json")
	res, err = htc.Do(r)
	if suite.NoError(err) {
		suite.Equal(http.StatusUnauthorized, res.StatusCode)
	}
	// happy path
	var token string
	token, err = user.BuildToken("mklimuk", "Michal", 3)
	suite.NoError(err)
	usr.On("CheckToken", req.Token, req.Update).Return(token, c, nil).Once()
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
