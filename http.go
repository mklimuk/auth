package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/render"
	log "github.com/sirupsen/logrus"
)

//Manager is an access layer for user-related operations
type UserLoginHandler interface {
	Login(username, password string) (string, error)
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
	CheckToken(token string, update bool) (string, *Claims, error)
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
				renderErrorJSON(w, r, http.StatusUnauthorized, "authorization bearer token not present")
				return
			}
			token, cs, err := auth.CheckToken(token, true)
			if err != nil {
				log.Infof("[auth_api] authorization error: %s", err.Error())
				renderErrorJSON(w, r, http.StatusUnauthorized, fmt.Sprintf("unauthorized: %s", err.Error()))
				return
			}
			u := newUser()
			defer returnUser(u)
			err = auth.Get(cs.Id, u)
			if err != nil {
				msg := fmt.Sprintf("[auth_api] error getting user: %s", err.Error())
				log.Errorf(msg)
				renderErrorJSON(w, r, http.StatusInternalServerError, msg)
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
		err := auth.Logout(u)
		if err != nil {
			msg := fmt.Sprintf("[auth_api] unexpected error during user '%s' logout: %s", u.Username, err.Error())
			log.Error(msg)
			renderErrorJSON(w, r, http.StatusInternalServerError, msg)
			return
		}
	}
}

func LoginHandler(auth UserLoginHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		usr := new(User)
		defer r.Body.Close()
		err := render.DecodeJSON(r.Body, usr)
		if err != nil {
			renderErrorJSON(w, r, http.StatusBadRequest, err.Error())
			return
		}
		token, err := auth.Login(usr.Username, usr.Password)
		if err != nil {
			if err == ErrBadRequest {
				renderErrorJSON(w, r, http.StatusBadRequest, "bad request")
				return
			}
			if err == ErrWrongUserPass || err == ErrNotFound {
				renderErrorJSON(w, r, http.StatusUnauthorized, "wrong username or password")
				return
			}
			msg := fmt.Sprintf("[auth_api] unexpected error during user '%s' signin: %s", usr.Username, err.Error())
			log.Error(msg)
			renderErrorJSON(w, r, http.StatusInternalServerError, msg)
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
			renderErrorJSON(w, r, http.StatusUnauthorized, "operation unauthorized")
		}
		users, err := auth.GetAll()
		if err != nil {
			msg := fmt.Sprintf("[auth_api] error getting list of users: %s", err.Error())
			log.Errorf(msg)
			renderErrorJSON(w, r, http.StatusInternalServerError, msg)
			return
		}
		render.Status(r, http.StatusOK)
		render.JSON(w, r, users)
	}
}

func CreateUserHandler(auth UserAdmin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := Get(r.Context())
		if u.Rigths < adminRights {
			renderErrorJSON(w, r, http.StatusUnauthorized, "operation unauthorized")
		}
		usr := new(User)
		defer r.Body.Close()
		err := render.DecodeJSON(r.Body, usr)
		if err != nil {
			renderErrorJSON(w, r, http.StatusBadRequest, err.Error())
			return
		}
		err = auth.Create(usr)
		if err != nil {
			if err == ErrBadRequest {
				renderErrorJSON(w, r, http.StatusBadRequest, "bad request")
				return
			}
			if err == ErrExists {
				renderErrorJSON(w, r, http.StatusConflict, "user already exists")
				return
			}
			msg := fmt.Sprintf("[auth_api] unexpected error during user creation: %s", err.Error())
			log.Errorf(msg)
			renderErrorJSON(w, r, http.StatusInternalServerError, msg)
			return
		}
		render.Status(r, http.StatusOK)
		render.JSON(w, r, usr)
	}
}

func CheckTokenHandler(auth TokenChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := new(checkRequest)
		defer r.Body.Close()
		err := render.DecodeJSON(r.Body, req)
		if err != nil {
			renderErrorJSON(w, r, http.StatusBadRequest, err.Error())
			return
		}
		token, cs, err := auth.CheckToken(req.Token, req.Update)
		if err != nil {
			renderErrorJSON(w, r, http.StatusUnauthorized, fmt.Sprintf("error checking token: %s", err.Error()))
			return
		}
		render.Status(r, http.StatusOK)
		render.JSON(w, r, struct {
			Token  string  `json:"token"`
			Claims *Claims `json:"claims"`
		}{
			Token:  token,
			Claims: cs,
		})
	}
}

func renderErrorJSON(w http.ResponseWriter, r *http.Request, status int, err string) {
	render.Status(r, status)
	render.JSON(w, r, struct {
		Error string `json:"error"`
	}{err})
}
