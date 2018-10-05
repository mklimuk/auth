package auth

import (
	"github.com/asdine/storm"
	cgob "github.com/asdine/storm/codec/gob"
)

const (
	StoreBolt = "bolt"
	StoreDir  = "dir"
)

type Store interface {
	Save(*User) error
	Get(string, *User) error
	ByUsername(string, *User) error
	Delete(string) error
	All(page, pageSize int) ([]*User, error)
}

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
	return s, s.db.Init(new(User))
}

func (s *BoltStore) Save(u *User) error {
	err := s.db.Save(u)
	if err == storm.ErrAlreadyExists {
		return ErrExists
	}
	return err
}

func (s *BoltStore) Get(ID string, u *User) error {
	err := s.db.One("ID", ID, u)
	if err == storm.ErrNotFound {
		return nil
	}
	return err
}

func (s *BoltStore) ByUsername(username string, u *User) error {
	err := s.db.One("Username", username, u)
	if err == storm.ErrNotFound {
		return nil
	}
	return err
}

func (s *BoltStore) Delete(ID string) error {
	usr := newUser()
	defer returnUser(usr)
	err := s.Get(ID, usr)
	if err != nil {
		return err
	}
	if usr == nil {
		return ErrNotFound
	}
	return s.db.DeleteStruct(usr)
}

func (s *BoltStore) All(page, pageSize int) ([]*User, error) {
	var res []*User
	err := s.db.All(&res, storm.Skip(page*pageSize), storm.Limit(pageSize))
	if err == storm.ErrNotFound {
		return nil, nil
	}
	return res, err
}
