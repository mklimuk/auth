package config

import (
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"
)

/*
Version encapsulates application version and environment information
*/
type Version struct {
	APIVersion  string `json:"apiVersion"`
	Environment string `json:"env"`
	Version     string `json:"version"`
}

//Ver represents application version information
var Ver Version

const apiVersion = "1.0"

/*
ParseVersion parses the version file into Version
*/
func ParseVersion(path string) {
	var (
		v   []byte
		err error
	)
	if v, err = ioutil.ReadFile(path); err != nil {
		log.WithFields(log.Fields{"logger": "pc.config.version", "file": path}).
			Panicln("Could not read the version file")
	}
	Ver = Version{apiVersion, getEnv("ENV", "devel"), string(v)}
}

//getEnv returns environment variable if it is set or defaultValue otherwise
func getEnv(key string, defaultValue string) (val string) {
	if val = os.Getenv(key); val == "" {
		return defaultValue
	}
	return val
}
