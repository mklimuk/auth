package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/mklimuk/auth"
	yaml "gopkg.in/yaml.v2"
)

var errBadRequest = fmt.Errorf("bad request")

func main() {
	l := len(os.Args)
	if l < 2 {
		fmt.Printf("Command not provided\nUse 'code' for passcode or 'pass' for password based generator\n")
		return
	}
	var user *auth.User
	var err error
	switch os.Args[1] {
	case "code":
		user, err = generateWithPasscode(os.Args[2:])
	case "pass":
		user, err = generateWithPassword(os.Args[2:])
	default:
		fmt.Printf("[ERROR] unknown command: %s\n\nUse 'code' for passcode or 'pass' for password based generator", os.Args[1])
	}
	if err != nil {
		if err == errBadRequest {
			// error message is in help
			return
		}
		fmt.Printf("[ERROR] could not create user: %v\n", err)
		return
	}
	account, err := yaml.Marshal(user)
	if err != nil {
		fmt.Printf("[ERROR] could not marshal user: %v\n", err)
		return
	}
	fmt.Printf("%s", account)
}

func generateWithPasscode(args []string) (*auth.User, error) {
	l := len(args)
	if l < 4 {
		fmt.Printf(helpPasscode, l)
		return nil, errBadRequest
	}
	u := auth.NewDefaultManager(auth.NewNoopStore(), auth.Opts{})
	rights, err := strconv.Atoi(args[3])
	if err != nil {
		fmt.Printf("[ERROR] could not parse user rights (must be an integer): %v\n", err)
		return nil, err
	}
	user := &auth.User{
		Username: args[0],
		Passcode: args[1],
		Name:     args[2],
		Rigths:   rights,
	}
	err = u.Create(user)
	return user, err
}

func generateWithPassword(args []string) (*auth.User, error) {
	l := len(args)
	if l != 5 {
		fmt.Printf(helpPassword, l)
		return nil, errBadRequest
	}
	u := auth.NewDefaultManager(auth.NewNoopStore(), auth.Opts{PasswordSecret: []byte(args[4])})
	rights, err := strconv.Atoi(args[3])
	if err != nil {
		fmt.Printf("[ERROR] could not parse user rights (must be an integer): %v\n", err)
		return nil, err
	}
	user := &auth.User{
		Username: args[0],
		Password: args[1],
		Name:     args[2],
		Rigths:   rights,
	}
	err = u.Create(user)
	return user, err
}

const helpPassword = `
[ERROR] expected 5 arguments for password-based auth but found %d

command arguments:
	- username
	- password
	- full name
	- user rights level
	- hash salt
`

const helpPasscode = `
[ERROR] expected 4 arguments for passcode-based auth but found %d

command arguments:
	- username
	- passcode
	- full name
	- user rights level
`
