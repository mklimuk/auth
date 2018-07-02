package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/render"
	"github.com/mklimuk/auth/user"
	log "github.com/sirupsen/logrus"
)

type checkRequest struct {
	Token  string `json:"token"`
	Update bool   `json:"update"`
}

func UserAPI(usr user.Manager) func(router chi.Router) {
	return func(router chi.Router) {
		router.Post("/login", loginHandler(usr))
		router.Post("/logout", logoutHandler(usr))
		router.Post("/user", createUserHandler(usr))
		router.Put("/token/check", checkTokenHandler(usr))
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
			if err == user.ErrNotFound {
				renderErrorJSON(w, r, http.StatusNotFound, fmt.Sprintf("user %s not found", usr.Username))
				return
			}
			if err == user.ErrBadRequest {
				renderErrorJSON(w, r, http.StatusBadRequest, "bad request")
				return
			}
			if err == user.ErrWrongUserPass {
				renderErrorJSON(w, r, http.StatusUnauthorized, "wrong username or password")
				return
			}
			log.Errorf("unexpected error during signin process for user %s: %s", usr.Username, err.Error())
			renderErrorJSON(w, r, http.StatusInternalServerError, "wystąpił nieoczekiwany błąd podczas logowania")
			return
		}
		render.Status(r, http.StatusOK)
		render.JSON(w, r, struct {
			Token string `json:"token"`
		}{token})
	}
}

func logoutHandler(users user.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
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
			if err == user.ErrBadRequest {
				renderErrorJSON(w, r, http.StatusBadRequest, "bad request")
				return
			}
			log.Errorf("unexpected error during token check: %s", err.Error())
			renderErrorJSON(w, r, http.StatusInternalServerError, "wystąpił nieoczekiwany błąd tworzenia konta")
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
