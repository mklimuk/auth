package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	"github.com/mklimuk/auth/user"
	log "github.com/sirupsen/logrus"
)

type checkRequest struct {
	Token  string `json:"token"`
	Update bool   `json:"update"`
}

func UserAPI(usr user.Manager) func(chi.Router) {
	return func(r chi.Router) {
		r.Post("/login", loginHandler(usr))
		r.Post("/logout", logoutHandler(usr))
		r.Put("/token/check", checkTokenHandler(usr))
		protect := r.With(AuthMiddleware(usr))
		protect.Get("/", getAllHandler(usr))
		protect.Post("/", createUserHandler(usr))
	}
}

type ctx int

const (
	ctxUser ctx = iota
)

type userContext struct {
	User   *user.User
	Claims *user.Claims
}

func GetUser(c context.Context) *user.User {
	u := c.Value(ctxUser)
	if u == nil {
		return nil
	}
	return u.(*userContext).User
}

func AuthMiddleware(usr user.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				renderErrorJSON(w, r, http.StatusUnauthorized, "authorization bearer token not present")
				return
			}
			token := strings.TrimPrefix(h, "Bearer ")
			token, cs, err := usr.CheckToken(token, true)
			if err != nil {
				renderErrorJSON(w, r, http.StatusUnauthorized, fmt.Sprintf("unauthorized: %s", err.Error()))
				return
			}
			user, err := usr.Get(cs.Id)
			if err != nil {
				msg := fmt.Sprintf("error getting user: %s", err.Error())
				log.Errorf(msg)
				renderErrorJSON(w, r, http.StatusInternalServerError, msg)
				return
			}
			w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))
			c := context.WithValue(r.Context(), ctxUser, &userContext{Claims: cs, User: user})
			next.ServeHTTP(w, r.WithContext(c))
		}
		return http.HandlerFunc(fn)
	}
}

func loginHandler(users user.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		usr := new(user.User)
		defer r.Body.Close()
		err := render.DecodeJSON(r.Body, usr)
		if err != nil {
			renderErrorJSON(w, r, http.StatusBadRequest, err.Error())
			return
		}
		token, err := users.Login(usr.Username, usr.Password)
		if err != nil {
			if err == user.ErrBadRequest {
				renderErrorJSON(w, r, http.StatusBadRequest, "bad request")
				return
			}
			if err == user.ErrWrongUserPass {
				renderErrorJSON(w, r, http.StatusUnauthorized, "wrong username or password")
				return
			}
			msg := fmt.Sprintf("unexpected error during signin process for user %s: %s", usr.Username, err.Error())
			log.Error(msg)
			renderErrorJSON(w, r, http.StatusInternalServerError, msg)
			return
		}
		w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))
		w.WriteHeader(http.StatusOK)
	}
}

func logoutHandler(users user.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

func getAllHandler(users user.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := users.GetAll()
		if err != nil {
			log.Errorf("error getting list of all users: %s", err.Error())
			renderErrorJSON(w, r, http.StatusInternalServerError, "wystąpił nieoczekiwany błąd podczas pobierania danych")
			return
		}
		render.Status(r, http.StatusOK)
		render.JSON(w, r, u)
	}
}

func createUserHandler(users user.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		usr := new(user.User)
		defer r.Body.Close()
		err := render.DecodeJSON(r.Body, usr)
		if err != nil {
			renderErrorJSON(w, r, http.StatusBadRequest, err.Error())
			return
		}
		usr, err = users.Create(usr)
		if err != nil {
			if err == user.ErrBadRequest {
				renderErrorJSON(w, r, http.StatusBadRequest, "bad request")
				return
			}
			if err == user.ErrExists {
				renderErrorJSON(w, r, http.StatusConflict, "user already exists")
				return
			}
			log.Errorf("unexpected error during user creation: %s", err.Error())
			renderErrorJSON(w, r, http.StatusInternalServerError, "wystąpił nieoczekiwany błąd tworzenia konta")
			return
		}
		render.Status(r, http.StatusOK)
		render.JSON(w, r, usr)
	}
}

func checkTokenHandler(users user.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req := new(checkRequest)
		defer r.Body.Close()
		err := render.DecodeJSON(r.Body, req)
		if err != nil {
			renderErrorJSON(w, r, http.StatusBadRequest, err.Error())
			return
		}
		token, cs, err := users.CheckToken(req.Token, req.Update)
		if err != nil {
			renderErrorJSON(w, r, http.StatusUnauthorized, fmt.Sprintf("error checking token: %s", err.Error()))
			return
		}
		render.Status(r, http.StatusOK)
		render.JSON(w, r, struct {
			Token  string       `json:"token"`
			Claims *user.Claims `json:"claims"`
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
