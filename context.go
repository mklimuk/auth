package auth

import "context"

type ctx int

const (
	ctxUser ctx = iota
)

type userContext struct {
	User   *User
	Claims *Claims
}

func WithContext(ctx context.Context, user *User, cs *Claims) context.Context {
	return context.WithValue(ctx, ctxUser, &userContext{Claims: cs, User: user})
}

func ContextUser(c context.Context) *User {
	u := c.Value(ctxUser)
	if u == nil {
		return nil
	}
	return u.(*userContext).User
}
