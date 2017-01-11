package user

//User contains user properties
type User struct {
	Username string `json:"username" yaml:"username"`
	Name     string `json:"name" yaml:"name"`
	Password string `json:"password" yaml:"password"`
	Rigths   int    `json:"rights" yaml:"rights"`
}
