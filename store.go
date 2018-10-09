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
	ByPasscode(string, *User) error
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
		return ErrNotFound
	}
	return err
}

func (s *BoltStore) ByUsername(username string, u *User) error {
	err := s.db.One("Username", username, u)
	if err == storm.ErrNotFound {
		return ErrNotFound
	}
	return err
}

func (s *BoltStore) ByPasscode(pass string, u *User) error {
	err := s.db.One("Passcode", pass, u)
	if err == storm.ErrNotFound {
		return ErrNotFound
	}
	return err
}

func (s *BoltStore) Delete(ID string) error {
	usr := newUser()
	defer releaseUser(usr)
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

type NoopStore struct {
}

func NewNoopStore() *NoopStore {
	return &NoopStore{}
}

func (s *NoopStore) Save(*User) error {
	return nil
}

func (s *NoopStore) Get(string, *User) error {
	return nil
}

func (s *NoopStore) ByUsername(string, *User) error {
	return nil
}

func (s *NoopStore) ByPasscode(string, *User) error {
	return nil
}

func (s *NoopStore) Delete(string) error {
	return nil
}

func (s *NoopStore) All(page, pageSize int) ([]*User, error) {
	return nil, nil
}
