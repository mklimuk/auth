package acceptance

import (
	"flag"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/godog"
	"github.com/mklimuk/auth/acceptance/control"
	"github.com/mklimuk/auth/acceptance/driver"
)

var timeout = time.Duration(20) * time.Second

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	var skipBuild = flag.Bool("build.skip", false, "skips compiling and packaging (runs tests on the last available container version)")
	var skipCleanup = flag.Bool("cleanup.skip", false, "skips stopping and cleaning up system under test")
	flag.Parse()

	var err error
	var env control.Environment
	if env, err = control.NewEnvironment("../."); err != nil {
		fmt.Printf("Problem initializing environment: %s \n", err.Error())
		return 10
	}

	if *skipBuild == false {
		if err = env.Build(); err != nil {
			fmt.Printf("Could not compile sources: %s \n", err.Error())
			return 11
		}
	}

	if err = env.Run(); err != nil {
		fmt.Printf("Could not run system under test: %s \n", err.Error())
		return 12
	}

	if !*skipCleanup {
		defer env.Stop()
		defer env.Cleanup()
	}
	d := driver.New("http://husar.dev:11081")

	ok := make(chan bool)
	go StatusLoop(ok, d)

	select {
	case <-ok:
	case <-time.After(timeout):
		fmt.Printf("System under test status loop timeout")
		return 100
	}

	status := godog.RunWithOptions("husar-generator", func(s *godog.Suite) {
		FeatureContext(s, d)
	}, godog.Options{
		Format: "progress",
		Paths:  []string{"acceptance/features"},
	})

	return status
}

func StatusLoop(statusChannel chan bool, g driver.Generator) {
	var status bool
	var err error
	for {
		if status, err = g.CheckHealth(); status == true {
			statusChannel <- true
			return
		}
		if err != nil {
			fmt.Printf("Error checking health: %s \n", err.Error())
		}
		time.Sleep(time.Duration(5) * time.Second)
	}
}
