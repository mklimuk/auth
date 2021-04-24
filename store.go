package auth

import (
	"fmt"

	"github.com/asdine/storm"
	cgob "github.com/asdine/storm/codec/gob"
)

var _ UserStore = &BoltStore{}
var _ UserTokenStore = &BoltStore{}

type BoltStore struct {
	path string
	db   *storm.DB
}

func NewBoltStore(path string) (*BoltStore, error) {
	s := &BoltStore{
		path: path,
	}
	var err error
	s.db, err = storm.Open(s.path, storm.Codec(cgob.Codec))
	if err != nil {
		return s, err
	}
	err = s.db.Init(&User{})
	if err != nil {
		return s, fmt.Errorf("could not init user: %w", err)
	}
	err = s.db.Init(&Token{})
	if err != nil {
		return s, fmt.Errorf("could not init user: %w", err)
	}
	return s, nil
}

func (s *BoltStore) SaveUser(u User) error {
	err := s.db.Save(&u)
	if err == storm.ErrAlreadyExists {
		return ErrExists
	}
	return err
}

func (s *BoltStore) SaveToken(t Token) error {
	err := s.db.Save(&t)
	if err == storm.ErrAlreadyExists {
		return ErrExists
	}
	return err
}

func (s *BoltStore) GetUser(ID string, u *User) error {
	err := s.db.One("ID", ID, u)
	if err == storm.ErrNotFound {
		return ErrNotFound
	}
	return err
}

func (s *BoltStore) GetUserByUsername(username string, u *User) error {
	err := s.db.One("Username", username, u)
	if err == storm.ErrNotFound {
		return ErrNotFound
	}
	return err
}

func (s *BoltStore) GetUserToken(value string, t *Token) error {
	err := s.db.One("Token", value, t)
	if err == storm.ErrNotFound {
		return ErrNotFound
	}
	return err
}

func (s *BoltStore) GetUserByPasscode(pass string, u *User) error {
	err := s.db.One("Passcode", pass, u)
	if err == storm.ErrNotFound {
		return ErrNotFound
	}
	return err
}

func (s *BoltStore) DeleteUser(ID string) error {
	usr := newUser()
	defer returnUser(usr)
	err := s.GetUser(ID, usr)
	if err != nil {
		return err
	}
	if usr == nil {
		return ErrNotFound
	}
	return s.db.DeleteStruct(usr)
}

func (s *BoltStore) AllUsers(page, pageSize int) ([]*User, error) {
	var res []*User
	err := s.db.All(&res, storm.Skip(page*pageSize), storm.Limit(pageSize))
	if err == storm.ErrNotFound {
		return nil, nil
	}
	return res, err
}
