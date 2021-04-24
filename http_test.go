package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func testCtxHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := ContextUser(r.Context())
		if assert.NotNil(t, u) {
			assert.Equal(t, "test1", u.Username)
		}
	}
}

func TestProtected(t *testing.T) {
	auth := &managerMock{}
	router := http.NewServeMux()
	router.Handle("/", Middleware(auth)(testCtxHandler(t)))
	router.Handle("/login", LoginHandler(auth))
	serv := httptest.NewServer(router)
	defer serv.Close()
	res, err := http.Get(fmt.Sprintf("%s%s", serv.URL, "/"))
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	b, err := json.Marshal(&User{Username: "test1", Password: "pass"})
	auth.On("Login", mock.AnythingOfType("*auth.User")).Return("abcd", nil).Once()
	htc := &http.Client{Timeout: 100 * time.Millisecond}
	r, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s%s", serv.URL, "/login"), bytes.NewReader(b))
	require.NoError(t, err)
	r.Header.Set("Content-Type", "application/x.login.req+json")
	res, err = htc.Do(r)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	tok := res.Header.Get("Authorization")
	assert.NotEmpty(t, tok)
	token := strings.TrimPrefix(tok, "Bearer ")
	assert.NotEmpty(t, token)
	// test using received token
	r, err = http.NewRequest(http.MethodGet, fmt.Sprintf("%s%s", serv.URL, "/testctx"), nil)
	require.NoError(t, err)
	r.Header.Set("Authorization", tok)
	// initial check token validates the token
	auth.On("ValidateToken", token, mock.AnythingOfType("*auth.Claims"), true, Scope(0)).Run(func(args mock.Arguments) {
		args.Get(1).(*Claims).Id = "uid1"
	}).Return(token, nil).Once()
	auth.On("GetUserByUsername", "uid1", mock.AnythingOfType("*auth.User")).Run(func(a mock.Arguments) {
		u := a[1].(*User)
		u.Username = "test1"
		u.Scope = 7
	}).Return(nil).Once()
	res, err = htc.Do(r)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	auth.AssertExpectations(t)
}

func TestLoginHandler(t *testing.T) {
	req := &User{Username: "test1", Password: "pass"}
	body, err := json.Marshal(&req)
	require.NoError(t, err)
	tests := []struct {
		name           string
		body           string
		init           func(*managerMock)
		expectedStatus int
	}{
		{"empty body", "", func(*managerMock) {}, http.StatusBadRequest},
		{"unauthorized", string(body), func(m *managerMock) {
			m.On("Login", mock.AnythingOfType("*auth.User")).Return("", ErrWrongUserPass).Once()
		}, http.StatusUnauthorized},
		{"internal error", string(body), func(m *managerMock) {
			m.On("Login", mock.AnythingOfType("*auth.User")).Return("", errors.New("generic error")).Once()
		}, http.StatusInternalServerError},
		{"happy path", string(body), func(m *managerMock) {
			m.On("Login", mock.AnythingOfType("*auth.User")).Return("abcd", nil).Once()
		}, http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, "/token/check", bytes.NewBufferString(test.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x.login.req+json")
			res := httptest.NewRecorder()
			auth := &managerMock{}
			test.init(auth)
			LoginHandler(auth).ServeHTTP(res, req)
			if !assert.Equal(t, test.expectedStatus, res.Result().StatusCode) {
				dump, _ := httputil.DumpResponse(res.Result(), true)
				fmt.Println(string(dump))
			}
		})
	}
}

func TestCheckTokenHandler(t *testing.T) {
	check := &CheckRequest{
		Token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0ODUzNDUzOTEsInVzZXJuYW1lIjoibWljaGFsIiwibmFtZSI6Ik1pY2hhbCBLbGltdWsiLCJwZXJtaXNzaW9ucyI6N30.a-Uh1Z_5m7Jy3GBJbjAZfYqC9uYaIFhM4HKnNb5fwZ4",
		Update: true,
	}
	checkBody, err := json.Marshal(&check)
	require.NoError(t, err)
	tests := []struct {
		name           string
		body           string
		init           func(*managerMock)
		expectedStatus int
	}{
		{"empty body", "", func(*managerMock) {}, http.StatusBadRequest},
		{"unauthorized", string(checkBody), func(m *managerMock) {
			m.On("ValidateToken", check.Token, mock.AnythingOfType("*auth.Claims"), check.Update, check.Scope).Run(func(args mock.Arguments) {
				args.Get(1).(*Claims).Username = "mklimuk"
			}).Return(check.Token, fmt.Errorf("unauthorized")).Once()
		}, http.StatusUnauthorized},
		{"happy path", string(checkBody), func(m *managerMock) {
			m.On("ValidateToken", check.Token, mock.AnythingOfType("*auth.Claims"), check.Update, check.Scope).Run(func(args mock.Arguments) {
				args.Get(1).(*Claims).Username = "mklimuk"
			}).Return(check.Token, nil).Once()
		}, http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, "/token/check", bytes.NewBufferString(test.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x.token.check+json")
			res := httptest.NewRecorder()
			auth := &managerMock{}
			test.init(auth)
			CheckTokenHandler(auth).ServeHTTP(res, req)
			if !assert.Equal(t, test.expectedStatus, res.Result().StatusCode) {
				dump, _ := httputil.DumpResponse(res.Result(), true)
				fmt.Println(string(dump))
			}
		})
	}
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

func (m *managerMock) GetUser(ID string, u *User) error {
	args := m.Called(ID, u)
	return args.Error(0)
}

//GetAll is a mocked method
func (m *managerMock) GetAllUsers() ([]*User, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*User), args.Error(1)
}

//CheckJWT is a mocked method
func (m *managerMock) ValidateToken(token string, _ *User, c *Claims, scope Scope, update bool) (string, error) {
	args := m.Called(token, c, update, scope)
	return args.String(0), args.Error(1)
}
