package user

import (
	"io/ioutil"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
)

type StoreTestSuite struct {
	suite.Suite
}

func (suite *StoreTestSuite) SetupSuite() {
	log.SetLevel(log.DebugLevel)
}

func (suite *StoreTestSuite) TestCreate() {
	s, err := NewStoreWrapper()
	suite.NoError(err)
	u := &User{
		ID:       "abcdef",
		Username: "user",
		Password: "pass",
	}
	s.store.Save(u)

}

func TestStoreTestSuite(t *testing.T) {
	suite.Run(t, new(StoreTestSuite))
}

type StoreWrapper struct {
	store *BoltStore
	f     *os.File
}

func NewStoreWrapper() (*StoreWrapper, error) {
	w := new(StoreWrapper)
	var err error
	if w.f, err = ioutil.TempFile(os.TempDir(), "test_authstore"); err != nil {
		return w, err
	}
	w.store, err = NewBoltStore(w.f.Name())
	return w, err
}

func (w *StoreWrapper) Cleanup() {
	w.store.db.Close()
	os.Remove(w.f.Name())
}
