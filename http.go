package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi"
)

//UserLoginHandler is an access layer for user-related operations
type UserLoginHandler interface {
	Login(string, string) (string, error)
}

type UserLogoutHandler interface {
	Logout(User) error
}

type UserReader interface {
	GetUser(string, *User) error
	GetAllUsers() ([]*User, error)
}

type UserWriter interface {
	CreateUser(User) error
}

type TokenGenerator interface {
	GenerateUserToken(owner, description string, scope Scope, expires time.Time) (Token, error)
}

type TokenRemover interface {
	DeleteUserToken(id string, u *User) error
}

type TokenReader interface {
	GetUserTokens(string) ([]Token, error)
}

type UserReadWriter interface {
	UserReader
	UserWriter
}

type TokenValidator interface {
	ValidateToken(token string, user *User, claims *Claims, update bool) (string, error)
}

// Err is a json error wrapper
type Err struct {
	Error string `json:"error"`
}

func jsonErr(msg string) Err {
	return Err{Error: msg}
}

func jsonErrf(msg string, args ...interface{}) Err {
	return Err{Error: fmt.Sprintf(msg, args...)}
}

func parseAuthorizationHeader(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

func Middleware(validator TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.URL.Query().Get("token"), "Bearer ")
			if token == "" {
				token = parseAuthorizationHeader(r)
			}
			if token == "" {
				renderJSON(w, http.StatusUnauthorized, jsonErr("authorization bearer token not present"))
				return
			}
			u := newUser()
			defer returnUser(u)
			cs := newClaims()
			defer returnClaims(cs)
			token, err := validator.ValidateToken(token, u, cs, r.Header.Get("X-Auth-Renew") == "1")
			if err != nil {
				renderJSON(w, http.StatusUnauthorized, jsonErrf("invalid token: %v", err))
				return
			}
			w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))
			next.ServeHTTP(w, r.WithContext(WithContext(r.Context(), u, cs)))
		}
		return http.HandlerFunc(fn)
	}
}

func LogoutHandler(auth UserLogoutHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := ContextUser(r.Context())
		if u == nil {
			// we consider the user to be already logged out
			w.WriteHeader(http.StatusOK)
			return
		}
		err := auth.Logout(*u)
		if err != nil {
			renderJSON(w, http.StatusInternalServerError, jsonErrf("unexpected error: %v", err))
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func LoginHandler(auth UserLoginHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			renderJSON(w, http.StatusBadRequest, jsonErrf("could not decode request: %v", err))
			return
		}
		token, err := auth.Login(req.Username, req.Password)
		if err != nil {
			switch {
			case errors.Is(err, ErrWrongUserPass):
				renderJSON(w, http.StatusUnauthorized, jsonErr("wrong username or password"))
			case errors.Is(err, ErrNotFound):
				renderJSON(w, http.StatusUnauthorized, jsonErr("wrong username or password"))
			default:
				renderJSON(w, http.StatusInternalServerError, jsonErrf("unexpected error: %v", err))
			}
			return
		}
		w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))
		w.WriteHeader(http.StatusOK)
	}
}

func GetAllUsersHandler(reader UserReader, access Scope) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := ContextUser(r.Context())
		if !u.Scope.Is(access) {
			renderJSON(w, http.StatusUnauthorized, jsonErr("operation unauthorized"))
		}
		users, err := reader.GetAllUsers()
		if err != nil {
			renderJSON(w, http.StatusInternalServerError, jsonErrf("could not fetch users: %v", err))
			return
		}
		renderJSON(w, http.StatusOK, users)
	}
}

func CreateUserHandler(writer UserWriter, access Scope) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := ContextUser(r.Context())
		if !u.Scope.Is(access) {
			renderJSON(w, http.StatusUnauthorized, jsonErr("operation unauthorized"))
			return
		}
		var usr User
		err := json.NewDecoder(r.Body).Decode(&usr)
		if err != nil {
			renderJSON(w, http.StatusBadRequest, jsonErrf("could not decode request: %v", err))
			return
		}
		err = usr.Validate()
		if err != nil {
			renderJSON(w, http.StatusBadRequest, err)
			return
		}
		err = writer.CreateUser(usr)
		if err != nil {
			switch {
			case errors.Is(err, ErrExists):
				renderJSON(w, http.StatusConflict, jsonErr("user already exists"))
			default:
				renderJSON(w, http.StatusInternalServerError, jsonErrf("unexpected error: %v", err))
			}
			return
		}
		renderJSON(w, http.StatusOK, usr)
	}
}

func GetUserTokens(reader TokenReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := ContextUser(r.Context())
		tokens, err := reader.GetUserTokens(u.ID)
		if err != nil {
			renderJSON(w, http.StatusInternalServerError, jsonErrf("unexpected error: %v", err))
			return
		}
		renderJSON(w, http.StatusOK, tokens)
	}
}

func GenerateUserTokenHandler(writer TokenGenerator, access Scope) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := ContextUser(r.Context())
		if !u.Scope.Is(access) {
			fmt.Printf("%+v not %d\n", u, access)
			renderJSON(w, http.StatusUnauthorized, jsonErr("operation unauthorized"))
			return
		}
		var req struct {
			Description string    `json:"description"`
			Scope       int       `json:"scope"`
			ExpiresAt   time.Time `json:"expires_at"`
		}
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			renderJSON(w, http.StatusBadRequest, jsonErrf("could not decode request: %v", err))
			return
		}
		token, err := writer.GenerateUserToken(u.ID, req.Description, Scope(req.Scope), req.ExpiresAt)
		if err != nil {
			renderJSON(w, http.StatusInternalServerError, jsonErrf("unexpected error: %v", err))
			return
		}
		resp := struct {
			Token
			Value string `json:"value"`
		}{Token: token, Value: token.Token}
		renderJSON(w, http.StatusOK, resp)
	}
}

func DeleteUserToken(store TokenRemover) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := ContextUser(r.Context())
		id := chi.URLParam(r, "id")
		err := store.DeleteUserToken(id, u)
		if err != nil {
			renderJSON(w, http.StatusInternalServerError, jsonErrf("unexpected error: %v", err))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type CheckRequest struct {
	Token  string `json:"token"`
	Update bool   `json:"update"`
}

func CheckTokenHandler(validator TokenValidator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil {
			renderJSON(w, http.StatusBadRequest, jsonErr("could not decode request: empty body"))
			return
		}
		var req CheckRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			renderJSON(w, http.StatusBadRequest, jsonErrf("could not decode request: %v", err))
			return
		}
		cs := newClaims()
		defer returnClaims(cs)
		u := newUser()
		defer returnUser(u)
		token, err := validator.ValidateToken(req.Token, u, cs, req.Update)
		if err != nil {
			renderJSON(w, http.StatusUnauthorized, jsonErrf("invalid token: %v", err))
			return
		}
		renderJSON(w, http.StatusOK, struct {
			Token  string  `json:"token"`
			Claims *Claims `json:"claims"`
		}{
			Token:  token,
			Claims: cs,
		})
	}
}

func renderJSON(w http.ResponseWriter, status int, res interface{}) {
	data, err := json.Marshal(res)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
	}
	w.Header().Add("Content-MsgType", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}
