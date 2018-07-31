package config

import (
	"os"
)

/*
VersionContext encapsulates application version and environment information
*/
type VersionContext struct {
	APIVersion  string `json:"apiVersion"`
	Environment string `json:"env"`
	Version     string `json:"version"`
	GitCommit   string `json:"commit"`
	GitBranch   string `json:"branch"`
	BuildTime   string `json:"buildTime"`
}

const apiVersion = "1.0"

var Version = "latest"
var GitCommit = "..."
var GitBranch = "local"
var BuildTime = ""

func GetVersion() *VersionContext {
	return &VersionContext{
		Version:     Version,
		APIVersion:  apiVersion,
		Environment: getEnv("ENV", "devel"),
		GitCommit:   GitCommit,
		GitBranch:   GitBranch,
		BuildTime:   BuildTime,
	}
}

//getEnv returns environment variable if it is set or defaultValue otherwise
func getEnv(key string, defaultValue string) (val string) {
	if val = os.Getenv(key); val == "" {
		return defaultValue
	}
	return val
}
