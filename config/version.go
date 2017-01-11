package config

//Version is a struct for holding version file content
type Version struct {
	Version     string `yaml:"version" json:"version"`
	APIVersion  string `yaml:"api" json:"api"`
	Environment string `json:"environment"`
}

const apiVersion = "1.0"
