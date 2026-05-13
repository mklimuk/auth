package auth

import "strconv"

type Scope int

func (s Scope) Is(other Scope) bool {
	return s&other > 0
}

func (s Scope) String() string {
	if desc := Scopes[s]; desc != "" {
		return desc
	}
	return strconv.Itoa(int(s))
}

// Scopes can be overridden to provide human friendly scope descriptions
var Scopes = map[Scope]string{}
