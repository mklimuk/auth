package config

import (
	"io/ioutil"

	log "github.com/Sirupsen/logrus"
	"github.com/mklimuk/husar/util"
	yaml "gopkg.in/yaml.v2"
)

//Config holds the current configuration
var Config Configuration

//Ver represents application version information
var Ver Version

const versionFile = "/var/husar/version.yml"

/*
Parse parses the configuration file into Config
*/
func Parse(path *string) string {
	var file []byte
	var err error
	if file, err = ioutil.ReadFile(*path); err != nil {
		log.WithFields(log.Fields{
			"file": *path,
		}).Panicln("Could not read the configuration file")
	}
	if err = yaml.Unmarshal(file, &Config); err != nil {
		log.WithFields(log.Fields{
			"file": *path,
		}).Panicln("Could not parse the configuration file")
	}
	if file, err = ioutil.ReadFile(versionFile); err != nil {
		log.WithFields(log.Fields{
			"file": versionFile,
		}).Panicln("Could not read the version file")
	}
	if err = yaml.Unmarshal(file, &Ver); err != nil {
		log.WithFields(log.Fields{
			"file": versionFile,
		}).Panicln("Could not parse the version file")
	}
	Ver.APIVersion = apiVersion
	Ver.Environment = util.GetEnv("ENV", "")
	return string(file)
}
