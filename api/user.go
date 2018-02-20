package api

import (
	"net/http"

	"github.com/mklimuk/auth/user"
	"github.com/mklimuk/goerr"
	"github.com/mklimuk/husar/rest"

	log "github.com/sirupsen/logrus"
	"github.com/gin-gonic/gin"
)

type userAPI struct {
	usr user.Manager
}

type checkRequest struct {
	Token  string `json:"token"`
	Update bool   `json:"update"`
}

//NewUserAPI is the user API constructor
func NewUserAPI(usr user.Manager) rest.API {
	c := userAPI{usr}
	return rest.API(&c)
}

//Routes initializes and returns all catalog API routes
func (c *userAPI) AddRoutes(router *gin.Engine) {
	router.POST("/login", c.login)
	router.POST("/logout", c.logout)
	router.POST("/user", c.createUser)
	router.POST("/token/check", c.checkToken)
}

func (c *userAPI) login(ctx *gin.Context) {
	defer rest.ErrorHandler(ctx)
	var err error
	l := new(user.User)
	if err = ctx.BindJSON(l); err != nil {
		log.WithFields(log.Fields{"logger": "auth.api", "method": "login", "error": err}).
			Warn("Could not parse request")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Could not parse input", "details": err.Error()})
		return
	}
	var token string
	if token, err = c.usr.Login(l.Username, l.Password); err != nil {
		switch goerr.GetType(err) {
		case goerr.NotFound:
			ctx.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		case goerr.Unauthorized:
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
			return
		default:
			log.WithFields(log.Fields{"logger": "auth.api", "method": "login", "error": err}).
				WithError(err).Error("Error processing login request")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal error occured", "details": err.Error()})
			return
		}
	}
	ctx.JSON(http.StatusOK, gin.H{"token": token})
}

func (c *userAPI) logout(ctx *gin.Context) {
	defer rest.ErrorHandler(ctx)
	ctx.AbortWithStatus(http.StatusOK)
}

func (c *userAPI) createUser(ctx *gin.Context) {
	defer rest.ErrorHandler(ctx)
	var err error
	u := new(user.User)
	if err = ctx.BindJSON(u); err != nil {
		log.WithFields(log.Fields{"logger": "auth.api", "method": "createUser", "error": err}).
			Warn("Could not parse request")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Could not parse input", "details": err.Error()})
		return
	}
	if u, err = c.usr.Create(u); err != nil {
		switch goerr.GetType(err) {
		case goerr.NotFound:
			ctx.JSON(http.StatusNotFound, goerr.GetCtx(err))
			return
		case goerr.BadRequest:
			ctx.JSON(http.StatusBadRequest, goerr.GetCtx(err))
			return
		case goerr.Unauthorized:
			ctx.JSON(http.StatusUnauthorized, goerr.GetCtx(err))
			return
		default:
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Internal error occured", "details": err.Error()})
			return
		}
	}
	ctx.YAML(http.StatusOK, u)
}

func (c *userAPI) checkToken(ctx *gin.Context) {
	defer rest.ErrorHandler(ctx)
	var err error
	req := new(checkRequest)
	if err = ctx.BindJSON(req); err != nil {
		log.WithFields(log.Fields{"logger": "auth.api", "method": "checkToken", "error": err}).
			Warn("Could not parse request")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Could not parse input", "details": err.Error()})
		return
	}
	var token string
	var cs *user.Claims
	if token, cs, err = c.usr.CheckToken(req.Token, req.Update); err != nil {
		switch goerr.GetType(err) {
		case goerr.BadRequest:
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "details": err.Error()})
			return
		default:
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token", "details": err.Error()})
			return
		}
	}
	ctx.JSON(http.StatusOK, gin.H{"token": token, "claims": cs})
}
