package main

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"testing"
)

func TestGenerate(t *testing.T) {
	u, err := generateWithPassword([]string{"pkp", "okecie", "operator", "1", "m!ch4l_"})
	account, err := yaml.Marshal(u)
	if err != nil {
		fmt.Printf("[ERROR] could not marshal user: %v\n", err)
		return
	}
	fmt.Printf("%s", account)
}
