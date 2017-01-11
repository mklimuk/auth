package config

import (
	"time"

	"github.com/mklimuk/auth/user"
)

/*
Configuration is a struct containing different configuration options
*/
type Configuration struct {
	Users []*user.User `yaml:"users"`
}

//Timezone is a reference timezone for the system
var Timezone, _ = time.LoadLocation("Europe/Warsaw")
