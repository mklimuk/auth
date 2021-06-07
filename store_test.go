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

func TestTokens(t *testing.T) {
	s, err := NewStoreWrapper()
	require.NoError(t, err)
	assert.NoError(t, s.store.SaveToken(Token{ID: "1", Owner: "test1", Scope: 7, Description: "test token", Token: "token1_1"}))
	assert.NoError(t, s.store.SaveToken(Token{ID: "2", Owner: "test1", Scope: 7, Description: "test token", Token: "token1_2"}))
	assert.NoError(t, s.store.SaveToken(Token{ID: "3", Owner: "test1", Scope: 7, Description: "test token", Token: "token1_3"}))
	assert.NoError(t, s.store.SaveToken(Token{ID: "4", Owner: "test2", Scope: 7, Description: "test token", Token: "token2_1"}))
	tokens, err := s.store.GetUserTokens("test3")
	assert.NoError(t, err)
	assert.Len(t, tokens, 0)
	tokens, err = s.store.GetUserTokens("test2")
	assert.NoError(t, err)
	assert.Len(t, tokens, 1)
	tokens, err = s.store.GetUserTokens("test1")
	assert.NoError(t, err)
	assert.Len(t, tokens, 3)
	var tok Token
	assert.NoError(t, s.store.GetUserToken("token1_2", &tok))
	assert.Equal(t, "test1", tok.Owner)
	assert.NoError(t, s.store.DeleteUserToken("5"))
	assert.NoError(t, s.store.DeleteUserToken("3"))
	tokens, err = s.store.GetUserTokens("test1")
	assert.NoError(t, err)
	assert.Len(t, tokens, 2)
}

type StoreWrapper struct {
	store *BoltStore
	f     *os.File
}

func NewStoreWrapper() (*StoreWrapper, error) {
	w := &StoreWrapper{}
	var err error
	if w.f, err = ioutil.TempFile(os.TempDir(), "test_authstore"); err != nil {
		return w, err
	}
	w.store, err = NewBoltStore(w.f.Name())
	return w, err
}

func (w *StoreWrapper) Cleanup() {
	_ = w.store.db.Close()
	_ = os.Remove(w.f.Name())
}
