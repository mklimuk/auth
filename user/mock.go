package user

import "github.com/stretchr/testify/mock"

//ManagerMock is a mockup of the user manager service
type ManagerMock struct {
	mock.Mock
}

//Login is a mocked method
func (m *ManagerMock) Login(username, password string) (string, error) {
	args := m.Called(username, password)
	return args.String(0), args.Error(1)
}

//Create is a mocked method
func (m *ManagerMock) Create(u *User) (*User, error) {
	args := m.Called(u)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *ManagerMock) Get(ID string) (*User, error) {
	args := m.Called(ID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

//GetAll is a mocked method
func (m *ManagerMock) GetAll() ([]*User, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*User), args.Error(1)
}

//CheckToken is a mocked method
func (m *ManagerMock) CheckToken(token string, update bool) (string, *Claims, error) {
	args := m.Called(token, update)
	if args.Get(1) == nil {
		return args.String(0), nil, args.Error(2)
	}
	return args.String(0), args.Get(1).(*Claims), args.Error(2)
}

func (m *ManagerMock) ValidToken(token string) bool {
	args := m.Called(token)
	return args.Bool(0)
}

type StoreMock struct {
	mock.Mock
}

func (m *StoreMock) Save(u *User) error {
	args := m.Called(u)
	return args.Error(0)
}

func (m *StoreMock) Get(ID string) (*User, error) {
	args := m.Called(ID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}
func (m *StoreMock) ByUsername(username string) (*User, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func (m *StoreMock) Delete(ID string) (*User, error) {
	args := m.Called(ID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}
func (m *StoreMock) All(page, pageSize int) ([]*User, error) {
	args := m.Called(page, pageSize)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*User), args.Error(1)
}
