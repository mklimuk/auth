package control

import (
	"fmt"
	"os"
	"os/exec"
)

const compileFilename = "compile.sh"
const runFilename = "run.sh"
const stopFilename = "stop.sh"
const cleanupFilename = "cleanup.sh"
const packageFilename = "package.sh"
const defaultVersion = "acceptance"

//Environment controls basic docker compose operations on predefined compose files
type Environment interface {
	Build() error
	Run() error
	Stop() error
	Cleanup() error
}

type environment struct {
	basePath    string
	compilePath string
	runPath     string
	stopPath    string
	cleanupPath string
	packagePath string
}

//NewEnvironment is the compose driver constructor
func NewEnvironment(basePath string) (Environment, error) {
	c := environment{basePath: basePath}
	if err := c.init(); err != nil {
		return nil, err
	}
	return Environment(&c), nil
}

//init tests the current path for presence of appropriate compose files, checks docker compose version
//and initializes required paths
func (c *environment) init() error {
	//check if we are in the correct folder
	var err error
	os.Chdir(c.basePath)
	path, _ := os.Getwd() //should be the project's root
	fmt.Println(path)
	c.compilePath = fmt.Sprintf("%s/%s", path, compileFilename)
	c.runPath = fmt.Sprintf("%s/%s", path, runFilename)
	c.stopPath = fmt.Sprintf("%s/%s", path, stopFilename)
	c.cleanupPath = fmt.Sprintf("%s/%s", path, cleanupFilename)
	c.packagePath = fmt.Sprintf("%s/%s", path, packageFilename)

	if _, err = os.Stat(c.compilePath); err != nil {
		return err
	}
	if _, err = os.Stat(c.runPath); err != nil {
		return err
	}
	if _, err = os.Stat(c.stopPath); err != nil {
		return err
	}
	if _, err = os.Stat(c.cleanupPath); err != nil {
		return err
	}

	//check if compose is available
	cmd := exec.Command("docker-compose", "version")
	var out []byte
	out, err = cmd.CombinedOutput()
	fmt.Printf(string(out))
	return err
}

//Compile runs the compile script
func (c *environment) Build() error {
	if err := runAndPrintOut(c.compilePath); err != nil {
		return err
	}
	return runAndPrintOut(c.packagePath)
}

//Run runs docker compose using run.yml compose file in the background
func (c *environment) Run() error {
	return runAndPrintOut(c.runPath)
}

//Cleanup containers deletes docker containers created by Run()
func (c *environment) Cleanup() error {
	return runAndPrintOut(c.cleanupPath)
}

//Stop runs stop script
func (c *environment) Stop() error {
	return runAndPrintOut(c.stopPath)
}

func runAndPrintOut(scriptPath string) error {
	cmd := exec.Command(scriptPath, defaultVersion)
	var out []byte
	var err error
	out, err = cmd.CombinedOutput()
	fmt.Printf(string(out))
	return err
}
