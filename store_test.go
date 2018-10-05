package auth

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
		ID:       "uid1",
		Username: "user1",
		Password: "pass",
	}
	err = s.store.Save(u)
	suite.NoError(err)
	u = &User{
		ID:       "uid2",
		Username: "user2",
		Password: "pass",
	}
	err = s.store.Save(u)
	suite.NoError(err)
	usr := newUser()
	defer returnUser(usr)
	err = s.store.ByUsername("user1", usr)
	suite.NoError(err)
	if suite.NotNil(usr) {
		suite.Equal("uid1", usr.ID)
	}
	users, err := s.store.All(0, 10)
	suite.NoError(err)
	if suite.NotNil(users) {
		suite.Len(users, 2)
	}

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
