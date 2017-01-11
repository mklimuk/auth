package control

import (
	"testing"

	log "github.com/Sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type EnvTestSuite struct {
	suite.Suite
	cont Environment
}

func (suite *EnvTestSuite) SetupSuite() {
	log.SetLevel(log.DebugLevel)
	suite.cont, _ = NewEnvironment("../..")
}

func (suite *EnvTestSuite) TestCompileStop() {
	a := assert.New(suite.T())
	err := suite.cont.Build()
	a.NoError(err)
	err = suite.cont.Stop()
	a.NoError(err)
	err = suite.cont.Cleanup()
	a.NoError(err)
}

func (suite *EnvTestSuite) TestUpDown() {
	a := assert.New(suite.T())
	err := suite.cont.Run()
	a.NoError(err)
	err = suite.cont.Stop()
	a.NoError(err)
	err = suite.cont.Cleanup()
	a.NoError(err)
}

func TestEnvTestSuite(t *testing.T) {
	suite.Run(t, new(EnvTestSuite))
}
