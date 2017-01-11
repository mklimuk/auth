package api

import (
	"net/http"

	"github.com/mklimuk/auth/config"
	"github.com/mklimuk/husar/rest"

	"github.com/gin-gonic/gin"
)

//NewControlAPI is a control constructor
func NewControlAPI() rest.API {
	c := controlAPI{}
	return rest.API(&c)
}

type controlAPI struct {
}

//AddRoutes initializes and returns all catalog API routes
func (c *controlAPI) AddRoutes(router *gin.Engine) {
	router.GET("/health", c.CheckHealth)
	router.GET("/version", c.VersionInfo)
}

func (c *controlAPI) CheckHealth(ctx *gin.Context) {
	defer rest.ErrorHandler(ctx)
	ctx.JSON(http.StatusOK, gin.H{"status": "OK"})
}

func (c *controlAPI) VersionInfo(ctx *gin.Context) {
	defer rest.ErrorHandler(ctx)
	ctx.JSON(http.StatusOK, config.Ver)
}
