package main

import (
	"fmt"
	"os"

	"github.com/mklimuk/auth/user"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	yaml "gopkg.in/yaml.v2"
)

func main() {
	os.Exit(run())
}

func run() int {
	app := cli.NewApp()
	app.EnableBashCompletion = true
	app.Name = "auth manager"
	app.Usage = "auth user management cli"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "store, s",
			Usage: "user store path to use",
		},
	}
	app.Action = func(c *cli.Context) error {
		return cli.ShowAppHelp(c)
	}
	app.Commands = cli.Commands{
		{
			Name:  "create",
			Usage: "create user",
			Action: func(c *cli.Context) error {
				if c.NArg() < 3 {
					return cli.ShowAppHelp(c)
				}
				path := c.String("store")
				var s user.Store
				var err error
				if path != "" {
					s, err = user.NewBoltStore(path)
					if err != nil {
						return err
					}
				}
				u := user.NewDefaultManager(s)
				arg := c.Args()
				user, err := u.Create(&user.User{
					Username: arg[0],
					Password: arg[1],
					Name:     arg[2],
				})
				if err != nil {
					return err
				}
				data, err := yaml.Marshal(user)
				if err != nil {
					return err
				}
				fmt.Println(string(data))
				return nil
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Errorf("unexpected error: %s ", err.Error())
		return 10
	}
	return 0
}
