package user

import "context"

type ctx int

const (
	ctxUser ctx = iota
)

type userContext struct {
	User   *User
	Claims *Claims
}

func Wrap(ctx context.Context, user *User, cs *Claims) context.Context {
	return context.WithValue(ctx, ctxUser, &userContext{Claims: cs, User: user})
}

func Get(c context.Context) *User {
	u := c.Value(ctxUser)
	if u == nil {
		return nil
	}
	return u.(*userContext).User
}

//User contains user properties
type User struct {
	ID       string `json:"id" yaml:"id" storm:"unique"`
	Username string `json:"username" yaml:"username" storm:"unique"`
	Name     string `json:"name" yaml:"name"`
	Password string `json:"password" yaml:"password"`
	Rigths   int    `json:"rights" yaml:"rights"`
}
