package user

import (
	"github.com/asdine/storm"
	cgob "github.com/asdine/storm/codec/gob"
)

const (
	StoreBolt = "bolt"
	StoreDir  = "dir"
)

type Store interface {
	Save(u *User) error
	Get(ID string) (*User, error)
	ByUsername(username string) (*User, error)
	Delete(ID string) (*User, error)
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

func (s *BoltStore) Get(ID string) (*User, error) {
	res := new(User)
	err := s.db.One("ID", ID, res)
	if err == storm.ErrNotFound {
		return nil, nil
	}
	return res, err
}

func (s *BoltStore) ByUsername(username string) (*User, error) {
	res := new(User)
	err := s.db.One("Username", username, res)
	if err == storm.ErrNotFound {
		return nil, nil
	}
	return res, err
}

func (s *BoltStore) Delete(ID string) (*User, error) {
	usr, err := s.Get(ID)
	if err != nil {
		return usr, err
	}
	if usr == nil {
		return nil, ErrNotFound
	}
	return usr, s.db.DeleteStruct(usr)
}

func (s *BoltStore) All(page, pageSize int) ([]*User, error) {
	var res []*User
	err := s.db.All(&res, storm.Skip(page*pageSize), storm.Limit(pageSize))
	if err == storm.ErrNotFound {
		return nil, nil
	}
	return res, err
}
