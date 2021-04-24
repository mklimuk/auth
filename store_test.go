package auth

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreate(t *testing.T) {
	s, err := NewStoreWrapper()
	require.NoError(t, err)
	u := User{
		ID:       "uid1",
		Username: "user1",
		Password: "pass",
	}
	err = s.store.SaveUser(u)
	assert.NoError(t, err)
	u = User{
		ID:       "uid2",
		Username: "user2",
		Password: "pass",
	}
	err = s.store.SaveUser(u)
	assert.NoError(t, err)
	usr := newUser()
	defer returnUser(usr)
	err = s.store.GetUserByUsername("user1", usr)
	require.NoError(t, err)
	if assert.NotNil(t, usr) {
		assert.Equal(t, "uid1", usr.ID)
	}
	users, err := s.store.AllUsers(0, 10)
	require.NoError(t, err)
	if assert.NotNil(t, users) {
		assert.Len(t, users, 2)
	}

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
