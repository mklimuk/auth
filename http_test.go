package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {
	token, err := buildJwt("test", "michal", "Michal Klimuk", []byte("passwd"), 60*time.Second, 7)
	require.NoError(t, err)
	tests := []struct {
		name         string
		token        string
		renew        string
		init         func(*serviceMock)
		expectStatus int
		expectCalled bool
	}{
		{"authorized", token, "", func(s *serviceMock) {
			s.On("ValidateToken", token, false).Return(token, nil)
		}, http.StatusOK, true},
		{"authorized renew", token, "1", func(s *serviceMock) {
			s.On("ValidateToken", token, true).Return(token, nil)
		}, http.StatusOK, true},
		{"invalid token", token, "", func(s *serviceMock) {
			s.On("ValidateToken", token, false).Return("", ErrTokenExpired)
		}, http.StatusUnauthorized, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &serviceMock{
				user: &User{
					Username: "michal",
					Name:     "Michal Klimuk",
					Password: "$2a$10$H9Bs2caL.R1mJNeNtJs07uGUtrWXwoHwWbQtwZ0yBEvZ9jJ1o4d26",
					Scope:    7,
				},
			}
			test.init(service)
			called := false
			mid := Middleware(service)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				u := ContextUser(r.Context())
				assert.Equal(t, service.user, u)
			}))
			req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/protected", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", test.token))
			req.Header.Set("X-Auth-Renew", test.renew)
			res := httptest.NewRecorder()
			mid.ServeHTTP(res, req)
			assert.Equal(t, test.expectStatus, res.Result().StatusCode)
			assert.Equal(t, test.expectCalled, called)
			if called {
				assert.NotEmpty(t, res.Result().Header.Get("Authorization"))
			}
		})
	}
}

func TestLoginHandler(t *testing.T) {
	req := &User{Username: "test1", Password: "pass"}
	body, err := json.Marshal(&req)
	require.NoError(t, err)
	tests := []struct {
		name           string
		body           string
		init           func(*serviceMock)
		expectedStatus int
	}{
		{"empty body", "", func(*serviceMock) {}, http.StatusBadRequest},
		{"unauthorized", string(body), func(m *serviceMock) {
			m.On("Login", "test1", "pass").Return("", ErrWrongUserPass).Once()
		}, http.StatusUnauthorized},
		{"internal error", string(body), func(m *serviceMock) {
			m.On("Login", "test1", "pass").Return("", errors.New("generic error")).Once()
		}, http.StatusInternalServerError},
		{"happy path", string(body), func(m *serviceMock) {
			m.On("Login", "test1", "pass").Return("abcd", nil).Once()
		}, http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, "/token/check", bytes.NewBufferString(test.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x.login.req+json")
			res := httptest.NewRecorder()
			auth := &serviceMock{}
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
		init           func(*serviceMock)
		expectedStatus int
	}{
		{"empty body", "", func(*serviceMock) {}, http.StatusBadRequest},
		{"unauthorized", string(checkBody), func(m *serviceMock) {
			m.On("ValidateToken", check.Token, check.Update).Return(check.Token, fmt.Errorf("unauthorized")).Once()
		}, http.StatusUnauthorized},
		{"happy path", string(checkBody), func(m *serviceMock) {
			m.On("ValidateToken", check.Token, check.Update).Return(check.Token, nil).Once()
		}, http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, "/token/check", bytes.NewBufferString(test.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x.token.check+json")
			res := httptest.NewRecorder()
			auth := &serviceMock{}
			test.init(auth)
			CheckTokenHandler(auth).ServeHTTP(res, req)
			if !assert.Equal(t, test.expectedStatus, res.Result().StatusCode) {
				dump, _ := httputil.DumpResponse(res.Result(), true)
				fmt.Println(string(dump))
			}
		})
	}
}

func TestCreateUserHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		scope          Scope
		init           func(*serviceMock)
		expectedStatus int
	}{
		{"valid", `{"username":"michal","password":"pass1234","name":"Michal Klimuk"}`, 7, func(s *serviceMock) {
			s.On("CreateUser", User{
				Username: "michal",
				Password: "pass1234",
				Name:     "Michal Klimuk",
			}).Return(nil)
		}, http.StatusOK},
		{"password too short", `{"username":"michal","password":"pass","name":"Michal Klimuk"}`, 7, func(s *serviceMock) {
			s.On("CreateUser", User{
				Username: "michal",
				Password: "pass1234",
				Name:     "Michal Klimuk",
			}).Return(nil)
		}, http.StatusBadRequest},
		{"internal error", `{"username":"michal","password":"pass1234","name":"Michal Klimuk"}`, 7, func(s *serviceMock) {
			s.On("CreateUser", User{
				Username: "michal",
				Password: "pass1234",
				Name:     "Michal Klimuk",
			}).Return(fmt.Errorf("dummy"))
		}, http.StatusInternalServerError},
		{"unauthorized", `{"username":"michal","password":"pass1234","name":"Michal Klimuk"}`, 8, func(s *serviceMock) {}, http.StatusUnauthorized},
		{"invalid request", `{"username":"michal","password":"pass1234","nam`, 7, func(s *serviceMock) {}, http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, "/token/check", bytes.NewBufferString(test.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x.token.check+json")
			req = req.WithContext(WithContext(context.Background(), &User{Scope: 7}, &Claims{}))
			res := httptest.NewRecorder()
			service := &serviceMock{}
			test.init(service)
			CreateUserHandler(service, test.scope).ServeHTTP(res, req)
			if !assert.Equal(t, test.expectedStatus, res.Result().StatusCode) {
				fmt.Println(res.Body.String())
			}
		})
	}
}

func TestGenerateUserTokenHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		scope          Scope
		init           func(*serviceMock)
		expectedStatus int
	}{
		{"valid", `{"scope":7,"expires_at":"2030-12-31T00:00:00Z"}`, 7, func(s *serviceMock) {
			s.On("GenerateUserToken", "test", Scope(7)).Return(Token{Owner: "test", Scope: 7}, nil)
		}, http.StatusOK},
		{"invalid scope", `{"scope":8,"expires_at":"2030-12-31T00:00:00Z"}`, 8, func(s *serviceMock) {
		}, http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPut, "/token/check", bytes.NewBufferString(test.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x.token.check+json")
			req = req.WithContext(WithContext(context.Background(), &User{ID: "test", Scope: 7}, &Claims{}))
			res := httptest.NewRecorder()
			service := &serviceMock{}
			test.init(service)
			GenerateUserTokenHandler(service, test.scope).ServeHTTP(res, req)
			if !assert.Equal(t, test.expectedStatus, res.Result().StatusCode) {
				fmt.Println(res.Body.String())
			}
		})
	}
}

type serviceMock struct {
	mock.Mock
	user   *User
	claims *Claims
}

func (m *serviceMock) GenerateUserToken(user, _ string, scope Scope, _ time.Time) (Token, error) {
	args := m.Called(user, scope)
	return args.Get(0).(Token), args.Error(1)
}

func (m *serviceMock) CreateUser(user User) error {
	args := m.Called(user)
	return args.Error(0)
}

//Login is a mocked method
func (m *serviceMock) Login(username, pass string) (string, error) {
	args := m.Called(username, pass)
	return args.String(0), args.Error(1)
}

//Create is a mocked method
func (m *serviceMock) Create(u *User) (*User, error) {
	args := m.Called(u)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *serviceMock) GetUser(ID string, u *User) error {
	args := m.Called(ID, u)
	return args.Error(0)
}

//GetAll is a mocked method
func (m *serviceMock) GetAllUsers() ([]*User, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*User), args.Error(1)
}

//CheckJWT is a mocked method
func (m *serviceMock) ValidateToken(token string, user *User, claims *Claims, update bool) (string, error) {
	args := m.Called(token, update)
	if m.user != nil {
		*user = *m.user
	}
	if m.claims != nil {
		*claims = *m.claims
	}
	return args.String(0), args.Error(1)
}
