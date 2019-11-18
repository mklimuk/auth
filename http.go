package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//Manager is an access layer for user-related operations
type UserLoginHandler interface {
	Login(*User) (string, error)
}

type UserLogoutHandler interface {
	Logout(User) error
}

type UserReader interface {
	Get(string, *User) error
}

type UserAdmin interface {
	Create(*User) error
	GetAll() ([]*User, error)
}

type TokenChecker interface {
	CheckToken(string, bool, *Claims) (string, error)
}

type UserTokenChecker interface {
	UserReader
	TokenChecker
}

type TokenValidator interface {
	ValidToken(token string) bool
}

const adminRights = 7

type checkRequest struct {
	Token  string `json:"token"`
	Update bool   `json:"update"`
}

func parseHeader(r *http.Request, header string) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(h, "Bearer ")
}

func AuthMiddleware(auth UserTokenChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			token := parseHeader(r, "Authorization")
			if token == "" {
				renderErrorJSON(w, http.StatusUnauthorized, "authorization bearer token not present")
				return
			}
			cs := newClaims()
			defer returnClaims(cs)
			token, err := auth.CheckToken(token, true, cs)
			if err != nil {
				log.Infof("[auth_api] authorization error: %v", err)
				renderErrorJSON(w, http.StatusUnauthorized, fmt.Sprintf("unauthorized: %v", err))
				return
			}
			u := newUser()
			defer releaseUser(u)
			err = auth.Get(cs.Id, u)
			if err != nil {
				msg := fmt.Sprintf("[auth_api] error getting user: %v", err)
				log.Errorf(msg)
				renderErrorJSON(w, http.StatusInternalServerError, msg)
				return
			}
			if r.Header.Get("X-Auth-Renew") == "1" {
				w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))
			}
			next.ServeHTTP(w, r.WithContext(Wrap(r.Context(), u, cs)))
		}
		return http.HandlerFunc(fn)
	}
}

func LogoutHandler(auth UserLogoutHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := Get(r.Context())
		if u == nil {
			// we consider the user to be already logged out
			w.WriteHeader(http.StatusOK)
			return
		}
		err := auth.Logout(*u)
		if err != nil {
			msg := fmt.Sprintf("[auth_api] unexpected error during user '%s' logout: %v", u.Username, err)
			log.Error(msg)
			renderErrorJSON(w, http.StatusInternalServerError, msg)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func LoginHandler(auth UserLoginHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		usr := newUser()
		defer releaseUser(usr)
		defer r.Body.Close()
		err := decodeJSON(r.Body, usr)
		if err != nil {
			renderErrorJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		token, err := auth.Login(usr)
		if err != nil {
			cause := errors.Cause(err)
			if cause == ErrBadRequest {
				renderErrorJSON(w, http.StatusBadRequest, "bad request")
				return
			}
			if cause == ErrWrongUserPass || cause == ErrNotFound {
				renderErrorJSON(w, http.StatusUnauthorized, "wrong username or password")
				return
			}
			msg := fmt.Sprintf("[auth_api] unexpected error during user '%s' signin: %v", usr.Username, err)
			log.Error(msg)
			renderErrorJSON(w, http.StatusInternalServerError, msg)
			return
		}
		w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))
		w.WriteHeader(http.StatusOK)
	}
}

func GetAllHandler(auth UserAdmin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := Get(r.Context())
		if u.Rigths < adminRights {
			renderErrorJSON(w, http.StatusUnauthorized, "operation unauthorized")
		}
		users, err := auth.GetAll()
		if err != nil {
			msg := fmt.Sprintf("[auth_api] error getting list of users: %v", err)
			log.Errorf(msg)
			renderErrorJSON(w, http.StatusInternalServerError, msg)
			return
		}
		renderJSON(w, users)
	}
}

func CreateUserHandler(auth UserAdmin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := Get(r.Context())
		if u.Rigths < adminRights {
			renderErrorJSON(w, http.StatusUnauthorized, "operation unauthorized")
		}
		usr := new(User)
		defer r.Body.Close()
		err := decodeJSON(r.Body, usr)
		if err != nil {
			renderErrorJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		err = auth.Create(usr)
		if err != nil {
			cause := errors.Cause(err)
			if cause == ErrBadRequest {
				renderErrorJSON(w, http.StatusBadRequest, "bad request")
				return
			}
			if cause == ErrExists {
				renderErrorJSON(w, http.StatusConflict, "user already exists")
				return
			}
			msg := fmt.Sprintf("[auth_api] unexpected error during user creation: %v", err)
			log.Errorf(msg)
			renderErrorJSON(w, http.StatusInternalServerError, msg)
			return
		}
		renderJSON(w, usr)
	}
}

func CheckTokenHandler(auth TokenChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := new(checkRequest)
		defer r.Body.Close()
		err := decodeJSON(r.Body, req)
		if err != nil {
			renderErrorJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		cs := newClaims()
		defer returnClaims(cs)
		token, err := auth.CheckToken(req.Token, req.Update, cs)
		if err != nil {
			renderErrorJSON(w, http.StatusUnauthorized, fmt.Sprintf("error checking token: %v", err))
			return
		}
		renderJSON(w, struct {
			Token  string  `json:"token"`
			Claims *Claims `json:"claims"`
		}{
			Token:  token,
			Claims: cs,
		})
	}
}

func renderErrorJSON(w http.ResponseWriter, status int, err string) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.Encode(struct {
		Error string `json:"error"`
	}{err})
}

func renderJSON(w http.ResponseWriter, res interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.Encode(res)
}

func decodeJSON(r io.Reader, v interface{}) error {
	defer io.Copy(ioutil.Discard, r)
	return json.NewDecoder(r).Decode(v)
}
