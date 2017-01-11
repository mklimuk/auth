package main

import (
	"fmt"
	"net/http"

	"github.com/mklimuk/auth/api"
	"github.com/mklimuk/auth/config"
	"github.com/mklimuk/auth/user"
	"github.com/mklimuk/husar/util"

	"github.com/gin-gonic/gin"

	log "github.com/Sirupsen/logrus"
)

const (
	defaultLogLevel = "warn"
	defaultConfig   = "/etc/husar/config.yml"
)

func main() {

	clog := log.WithFields(log.Fields{"logger": "auth.main"})

	level := util.GetEnv("LOG", defaultLogLevel)
	conf := util.GetEnv("CONFIG", defaultConfig)

	var err error
	var l log.Level
	if l, err = log.ParseLevel(level); err != nil {
		clog.WithField("level", level).Panicln("Invalid log level")
	}
	log.SetLevel(l)

	rawConf := config.Parse(&conf)
	fmt.Printf("Loaded configuration:\n %s\n", rawConf)

	clog.Info("Initializing services")
	usr := user.NewManager(config.Config.Users)

	clog.Info("Initializing REST router...")
	u := api.NewUserAPI(usr)
	c := api.NewControlAPI()
	router := gin.New()
	u.AddRoutes(router)
	c.AddRoutes(router)
	clog.Fatal(http.ListenAndServe(":8080", router))
}
