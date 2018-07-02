package user

//User contains user properties
type User struct {
	ID       string `json:"id" yaml:"id" storm:"unique"`
	Username string `json:"username" yaml:"username" storm:"unique"`
	Name     string `json:"name" yaml:"name"`
	Password string `json:"password" yaml:"password"`
	Rigths   int    `json:"rights" yaml:"rights"`
}
